# SPDX-License-Identifier: GPL-3.0-only
import logging
import os
import re
import shutil
import tempfile
import urllib
from collections.abc import Iterable, Iterator
from itertools import chain
from pathlib import Path
from tempfile import TemporaryDirectory
from types import TracebackType
from typing import TYPE_CHECKING, Any, Literal, NamedTuple, NoReturn, Optional

import git
from packageurl import PackageURL

from hermeto import APP_NAME
from hermeto.core.constants import Mode

if TYPE_CHECKING:
    from typing_extensions import Self

from hermeto.core.config import get_config
from hermeto.core.errors import (
    FetchError,
    InvalidInput,
    LockfileNotFound,
    NotAGitRepo,
    PackageManagerError,
    PackageRejected,
    UnexpectedFormat,
)
from hermeto.core.models.input import Request
from hermeto.core.models.output import EnvironmentVariable, RequestOutput
from hermeto.core.models.property_semantics import PropertySet
from hermeto.core.models.sbom import (
    PROXY_COMMENT,
    PROXY_REF_TYPE,
    Annotation,
    Component,
    ExternalReference,
    create_backend_annotation,
    spdx_now,
)
from hermeto.core.package_managers.gomod.go import (
    Go,
    GoWork,
    _get_go_work_path,
    _list_installed_toolchains,
    _list_toolchain_files,
    _ParsedModel,
    _select_toolchain,
)
from hermeto.core.package_managers.gomod.local import LocalModuleResolver
from hermeto.core.package_managers.gomod.utils import _clean_go_modcache, _go_exec_env
from hermeto.core.rooted_path import RootedPath
from hermeto.core.scm import GitSourceLocation, get_repo_for_path
from hermeto.core.utils import GIT_PRISTINE_ENV, load_json_stream
from hermeto.interface.logging import EnforcingModeLoggerAdapter

# NOTE: the 'extra' dict is unused right now, but it's a positional argument for the adapter class
log = EnforcingModeLoggerAdapter(logging.getLogger(__name__), {"enforcing_mode": Mode.STRICT})

ModuleDict = dict[str, Any]


class ParsedOrigin(_ParsedModel):
    """A Go module origin as returned by the -json option of go mod download (relevant fields only).

    See:
        go help mod download    (Origin struct in Module)
    """

    vcs: str
    url: str
    hash: str


class ParsedModule(_ParsedModel):
    """A Go module as returned by the -json option of various commands (relevant fields only).

    ``dir`` is Go's raw directory metadata, including for downloaded modules.
    ``local_path`` identifies validated source directories for locally sourced modules only.

    See:
        go help mod download    (Module struct)
        go help list            (Module struct)
    """

    path: str
    version: str | None = None
    main: bool = False
    replace: Optional["ParsedModule"] = None
    origin: Optional[ParsedOrigin] = None
    dir: str | None = None
    local_path: RootedPath | None = None


class ParsedPackage(_ParsedModel):
    """A Go package as returned by the -json option of go list (relevant fields only).

    See:
        go help list    (Package struct)
    """

    import_path: str
    standard: bool = False
    module: ParsedModule | None = None


class ResolvedGoModule(NamedTuple):
    """Contains the data for a resolved main module (a module in the user's repo)."""

    parsed_main_module: ParsedModule
    parsed_modules: Iterable[ParsedModule]
    parsed_packages: Iterable[ParsedPackage]
    modules_in_go_sum: frozenset["ModuleID"]


class Module(NamedTuple):
    """A Go module with relevant data for the SBOM generation.

    name: the resolved name for this module
    original_name: module's name as written in go.mod, before any replacement
    version: the resolved version for this module
    missing_hash_in_file: path (relative to repository root) to the go.sum file which should have
        had a checksum for this module but didn't
    proxy: the list of custom proxy URLs used to fetch this module, or None if the module was
        fetched directly from VCS or only via the canonical Go proxy (proxy.golang.org).
    source: optional GitSourceLocation to carry data necessary to construct vcs_url
    """

    name: str
    original_name: str
    version: str
    missing_hash_in_file: Path | None = None
    proxy: list[str] | None = None
    source: GitSourceLocation | None = None

    @property
    def purl(self) -> str:
        """Get the purl for this module."""
        purl = PackageURL(
            type="golang",
            name=self.name,
            version=self.version,
            qualifiers={"type": "module"} | _vcs_url_if_needed(self),
        )
        return purl.to_string()

    def get_external_refs(self) -> list[ExternalReference] | None:
        """Get external references for a module."""
        ref_rest = dict(type=PROXY_REF_TYPE, comment=PROXY_COMMENT)
        if self.proxy:
            return [ExternalReference(url=p, **ref_rest) for p in self.proxy]
        return None

    def to_component(self) -> Component:
        """Create a SBOM component for this module."""
        if self.missing_hash_in_file:
            missing_hash_in_file = frozenset([str(self.missing_hash_in_file)])
        else:
            missing_hash_in_file = frozenset()

        refs = self.get_external_refs()

        return Component(
            name=self.name,
            version=self.version,
            purl=self.purl,
            properties=PropertySet(missing_hash_in_file=missing_hash_in_file).to_properties(),
            external_references=refs,
        )


class Package(NamedTuple):
    """A Go package with relevant data for the SBOM generation.

    relative_path: the package path relative to its parent module's name
    module: parent module for this package
    """

    relative_path: str | None
    module: Module

    @property
    def name(self) -> str:
        """Get the name for this package based on the parent module's name."""
        if self.relative_path:
            return f"{self.module.name}/{self.relative_path}"

        return self.module.name

    @property
    def purl(self) -> str:
        """Get the purl for this package."""
        purl = PackageURL(
            type="golang",
            name=self.name,
            version=self.module.version,
            qualifiers={"type": "package"} | _vcs_url_if_needed(self.module),
        )
        return purl.to_string()

    def to_component(self) -> Component:
        """Create a SBOM component for this package."""
        return Component(
            name=self.name,
            version=self.module.version,
            purl=self.purl,
            external_references=self.module.get_external_refs(),
        )


def _vcs_url_if_needed(module: Module) -> dict[str, str]:
    """Determine whether a vcs_url qualifier is necessary and provide one."""
    if module.source is not None:
        # Locally sourced modules are consumed from a Git working tree, so their repository
        # provenance needs to be included in the PURL.
        return {"vcs_url": module.source.as_vcs_url_qualifier()}
    return dict()


class StandardPackage(NamedTuple):
    """A package from Go standard lib used in the SBOM generation.

    Standard lib packages lack a parent module and, consequentially, a version.
    """

    name: str

    @property
    def purl(self) -> str:
        """Get the purl for this package."""
        purl = PackageURL(type="golang", name=self.name, qualifiers={"type": "package"})
        return purl.to_string()

    def to_component(self) -> Component:
        """Create a SBOM component for this package."""
        # Note, these components come from the standard lib, they lack version, they
        # are not collected from a repository and are not present in the output directory.
        return Component(name=self.name, purl=self.purl)


ModuleID = tuple[str, str]


def _get_module_id(module: ParsedModule) -> ModuleID:
    """Identify a ParsedModule by its name and version/filepath.

    The main module, which doesn't have a version in its ParsedModule representation,
    gets the "." filepath.

    Note: if two IDs (include a filepath and) differ only by filepath, they may in fact identify
    the same module - different relative paths but the same absolute path. IDs that include
    a filepath are not universally unique, only locally unique within the dependencies of a main
    module.
    """
    if not (replace := module.replace):
        name = module.path
        version_or_path = module.version or "."
    elif replace.version:
        # module/name v1.0.0 => replace/name v1.2.3
        name = replace.path
        version_or_path = replace.version
    else:
        # module/name v1.0.0 => ./local/path
        name = module.path
        version_or_path = replace.path

    return name, version_or_path


def _get_proxy_for_module(module: ParsedModule) -> list[str] | None:
    """
    Returns None when the module was fetched directly from VCS (origin is set), or when
    the configured GOPROXY contains only canonical entries (proxy.golang.org, direct).
    When custom proxies are present, returns all configured proxy URLs except 'direct',
    including proxy.golang.org if set alongside custom proxies.
    """
    if module.origin:
        return None

    canonical_proxies = {"direct", "https://proxy.golang.org"}
    proxy_config = get_config().gomod.proxy_url

    proxies = [p.strip() for p in re.split(r"[|,]", proxy_config) if p.strip()]

    if not any(p not in canonical_proxies for p in proxies):
        return None

    return [p for p in proxies if p != "direct"]


def _create_modules_from_parsed_data(
    main_module_dir: RootedPath,
    parsed_modules: Iterable[ParsedModule],
    modules_in_go_sum: frozenset[ModuleID],
    local_module_resolver: LocalModuleResolver,
    go_work: GoWork | None,
) -> list[Module]:
    def _create_module(module: ParsedModule) -> Module:
        if module.local_path is not None:
            resolution = local_module_resolver.resolve(module.path, module.local_path)
            return Module(
                name=module.path,
                version=resolution.version,
                original_name=module.path,
                source=resolution.source,
            )

        mod_id = _get_module_id(module)
        name, version_or_path = mod_id
        original_name = module.path
        missing_hash_in_file = None

        version = version_or_path
        proxy = _get_proxy_for_module(module)

        if mod_id not in modules_in_go_sum:
            if go_work:
                go_work_subpath = go_work.rooted_path.subpath_from_root
                missing_hash_in_file = go_work_subpath.parent / "go.work.sum"
            else:
                missing_hash_in_file = main_module_dir.subpath_from_root / "go.sum"

            log.warning("checksum not found in %s: %s@%s", missing_hash_in_file, name, version)

        return Module(
            name=name,
            version=version,
            original_name=original_name,
            missing_hash_in_file=missing_hash_in_file,
            proxy=proxy,
        )

    return [_create_module(module) for module in parsed_modules]


def _create_packages_from_parsed_data(
    modules: list[Module], parsed_packages: Iterable[ParsedPackage]
) -> list[Package | StandardPackage]:
    # in case of replacements, the packages still refer to their parent module by its original name
    indexed_modules = {module.original_name: module for module in modules}

    def _create_package(package: ParsedPackage) -> Package | StandardPackage:
        if package.standard:
            return StandardPackage(name=package.import_path)

        if package.module is None:
            module = _find_parent_module_by_name(package)
        else:
            module = indexed_modules[package.module.path]

        relative_path = _resolve_package_relative_path(package, module)

        return Package(relative_path=relative_path, module=module)

    def _find_parent_module_by_name(package: ParsedPackage) -> Module:
        """Return the longest module name that is contained in package's import_path."""
        path = Path(package.import_path)

        matched_name = max(
            filter(path.is_relative_to, indexed_modules.keys()),
            key=len,  # type: ignore
            default=None,
        )

        if not matched_name:
            # This should be impossible
            raise RuntimeError("Package parent module was not found")

        return indexed_modules[matched_name]

    def _resolve_package_relative_path(package: ParsedPackage, module: Module) -> str:
        """Return the path for a package relative to its parent module original name."""
        relative_path = Path(package.import_path).relative_to(module.original_name)
        return str(relative_path).removeprefix(".")

    return [_create_package(package) for package in parsed_packages]


def _update_sbom_annotations(components: list[Component], annotations: list[Annotation]) -> None:
    """
    Update SBOM annotations with subjects from the provided components.

    If the annotations list is empty, a new annotation is created. Otherwise, the existing annotation
    is extended with more subjects. There is only one permissive mode use case for gomod at the moment.
    """
    subjects = {c.bom_ref for c in components}
    if annotations:
        annotations[0].subjects.update(subjects)
    else:
        annotations.append(
            Annotation(
                subjects=subjects,
                annotator={"organization": {"name": "red hat"}},
                timestamp=spdx_now(),
                text="hermeto:permissive-mode:gomod:vendor-directory-changed-after-vendoring",
            )
        )


def fetch_gomod_source(request: Request) -> RequestOutput:
    """
    Resolve and fetch gomod dependencies for a given request.

    :param request: the request to process
    :raises PackageRejected: if a file is not present for the gomod package manager
    :raises PackageManagerError: if failed to fetch gomod dependencies
    """
    config = get_config()
    enforcing_mode = config.mode
    subpaths = [str(package.path) for package in request.gomod_packages]

    if not subpaths:
        return RequestOutput.empty()

    if not (installed_toolchains := _list_installed_toolchains()):
        raise FetchError(
            "Could not find any installed Go toolchains in known locations",
            solution="Please make sure at least one go toolchain is installed in the system",
        )

    invalid_gomod_files = _find_missing_gomod_files(request.source_dir, subpaths)

    if invalid_gomod_files:
        raise LockfileNotFound(
            files=invalid_gomod_files,
            solution=(
                "Please double-check that you have specified correct paths to your Go modules"
            ),
        )

    components: list[Component] = []
    annotations: list[Annotation] = []

    local_module_resolver = LocalModuleResolver(request.source_dir)

    gomod_download_dir = request.output_dir.join_within_root("deps/gomod/pkg/mod/cache/download")
    gomod_download_dir.path.mkdir(exist_ok=True, parents=True)

    with GoCacheTemporaryDirectory(prefix=f"{APP_NAME}-") as tmp_dir:
        for subpath in subpaths:
            log.info("Fetching the gomod dependencies at subpath %s", subpath)
            go_work: GoWork | None = None

            vendor_diffs: list = []
            main_module_dir = request.source_dir.join_within_root(subpath)
            go = _select_toolchain(main_module_dir.join_within_root("go.mod"), installed_toolchains)
            if go is None:
                raise FetchError(
                    "Could not match any suitable Go toolchain for the job",
                    solution="Please make sure a suitable Go toolchain is installed on the system",
                )

            tmp_dir._go_instance = go
            if (go_work_path := _get_go_work_path(go, main_module_dir)) is not None:
                go_work = GoWork.from_file(go_work_path, go)

            try:
                resolve_result = _resolve_gomod(
                    main_module_dir, request, Path(tmp_dir.name), go, go_work
                )
            except PackageManagerError:
                log.error("Failed to fetch gomod dependencies")
                raise
            try:
                vendor_diffs = _vendor_change_list(main_module_dir)
            except NotAGitRepo:
                if enforcing_mode != Mode.PERMISSIVE:
                    raise
            if vendor_diffs:
                for d in vendor_diffs:
                    log.error_or_warn(
                        f"vendor changed: {d.change_type}\t{d.a_path or d.b_path}",
                        enforcing_mode=enforcing_mode,
                    )
                if enforcing_mode != Mode.PERMISSIVE:
                    raise PackageRejected(
                        reason=(
                            "The content of the vendor directory is not consistent with go.mod. "
                            "Please check the logs for more details."
                        ),
                        solution=(
                            "Please try running `go mod vendor` and committing the changes.\n"
                            "Note that you may need to `git add --force` ignored files in the vendor/ dir."
                        ),
                    )

            main_module = _create_main_module_from_parsed_data(
                local_module_resolver, resolve_result.parsed_main_module
            )

            modules = [main_module]
            modules.extend(
                _create_modules_from_parsed_data(
                    main_module_dir,
                    resolve_result.parsed_modules,
                    resolve_result.modules_in_go_sum,
                    local_module_resolver,
                    go_work,
                )
            )

            packages = _create_packages_from_parsed_data(modules, resolve_result.parsed_packages)

            module_components = [module.to_component() for module in modules]
            package_components = [package.to_component() for package in packages]
            subpath_components = module_components + package_components

            if vendor_diffs:
                _update_sbom_annotations(subpath_components, annotations)

            components.extend(subpath_components)

        tmp_download_cache_dir = Path(tmp_dir.name).joinpath("pkg/mod/cache/download")
        if tmp_download_cache_dir.exists():
            log.debug(
                "Adding dependencies from %s to %s",
                tmp_download_cache_dir,
                gomod_download_dir,
            )
            shutil.copytree(
                tmp_download_cache_dir,
                str(gomod_download_dir),
                dirs_exist_ok=True,
                ignore=_list_toolchain_files,
            )

    env_vars_template = {
        "GOCACHE": "${output_dir}/deps/gomod",
        "GOPATH": "${output_dir}/deps/gomod",
        "GOMODCACHE": "${output_dir}/deps/gomod/pkg/mod",
        "GOPROXY": "file://${GOMODCACHE}/cache/download",
        "GOSUMDB": "off",
    }
    env_vars_template.update(config.gomod.environment_variables)

    if backend_annotation := create_backend_annotation(components, "gomod"):
        annotations.append(backend_annotation)
    return RequestOutput.from_obj_list(
        components=components,
        environment_variables=[
            EnvironmentVariable(name=key, value=value) for key, value in env_vars_template.items()
        ],
        annotations=annotations,
    )


def _create_main_module_from_parsed_data(
    local_module_resolver: LocalModuleResolver,
    parsed_main_module: ParsedModule,
) -> Module:
    if parsed_main_module.local_path is None:
        raise RuntimeError(
            f"Local path was not identified for main module {parsed_main_module.path}"
        )

    resolution = local_module_resolver.resolve(
        parsed_main_module.path,
        parsed_main_module.local_path,
    )

    return Module(
        name=parsed_main_module.path,
        original_name=parsed_main_module.path,
        version=resolution.version,
        source=resolution.source,
    )


def _protect_against_symlinks(app_dir: RootedPath) -> None:
    """Try to prevent go subcommands from following suspicious symlinks.

    The go command doesn't particularly care if the files it reads are subpaths of the directory
    where it is executed. Check some of the common paths that the subcommands may read.

    :raises PathOutsideRoot: if go.mod, go.sum, vendor/modules.txt or any **/*.go file is a symlink
        that leads outside the source directory
    """

    def check_potential_symlink(relative_path: str | Path) -> None:
        app_dir.join_within_root(relative_path)

    # we purposefully skip checking go.work here because it is being checked elsewhere

    go_control_files = ["go.mod", "go.sum", "vendor/modules.txt"]
    go_sources_paths = [fp.relative_to(app_dir) for fp in app_dir.path.rglob("*.go")]

    # mypy doesn't see the object type from chain can only be a str or a Path and reports an error
    for p in chain(go_control_files, go_sources_paths):
        check_potential_symlink(p)  # type: ignore


def _find_missing_gomod_files(source_path: RootedPath, subpaths: list[str]) -> list[Path]:
    """
    Find all go modules with missing gomod files.

    These files will need to be present in order for the package manager to proceed with
    fetching the package sources.

    :param RequestBundleDir bundle_dir: the ``RequestBundleDir`` object for the request
    :param list subpaths: a list of subpaths in the source repository of gomod packages
    :return: a list containing all non-existing go.mod files across subpaths
    :rtype: list
    """
    invalid_gomod_files = []
    for subpath in subpaths:
        package_gomod_path = source_path.join_within_root(subpath, "go.mod").path
        log.debug(f"Testing for go mod file in {package_gomod_path}")
        if not package_gomod_path.exists():
            invalid_gomod_files.append(package_gomod_path)

    return invalid_gomod_files


def _disable_telemetry(go: Go, run_params: dict[str, Any]) -> None:
    telemetry = go(["env", "GOTELEMETRY"], run_params).rstrip()
    if telemetry and telemetry != "off":
        log.debug("Disabling Go telemetry")
        go(["telemetry", "off"], run_params)


def _go_list_deps(
    go: Go, pattern: Literal["./...", "all"], run_params: dict[str, Any]
) -> Iterator[ParsedPackage]:
    """Run go list -deps -json and return the parsed list of packages.

    The "./..." pattern returns the list of packages compiled into the final binary.

    The "all" pattern includes dependencies needed only for tests. Use it to get a more
    complete module list (roughly matching the list of downloaded modules).
    """
    cmd = ["list", "-e", "-deps", "-json=ImportPath,Module,Standard", pattern]
    return map(
        ParsedPackage.model_validate,
        load_json_stream(go(cmd, run_params)),
    )


def _parse_packages(
    go_work: GoWork | None, go: Go, run_params: dict[str, Any]
) -> Iterator[ParsedPackage]:
    """Return all Go packages for the project.

    Query the packages from the root of the project. If the project uses Go workspaces (1.18+) we
    additionally need to execute the query from every workspace module because 'go list' command
    isn't workspace aware and doesn't return all results if run just from the project root.

    :param go_work: GoWork instance wrapping the go.work file
    :param go: Go executable wrapper instance
    :param run_params: Additional run cmd params
    :return: ParsedPackage iterator
    """
    all_packages: Iterable[ParsedPackage] = []

    if go_work is None:
        log.debug("Querying for list of packages")
        all_packages = _go_list_deps(go, "./...", run_params)
    else:
        # If there are workspace modules we need to run 'list -e ./...' under every local module
        # path because 'go list' command isn't fully properly workspace context aware
        for wsp in go_work.workspace_paths:
            log.debug(f"Querying workspace module '{wsp}' for list of packages")

            packages = list(_go_list_deps(go, "./...", run_params | {"cwd": wsp}))
            all_packages = chain(all_packages, packages)
    return iter(all_packages)


def _determine_cache_path(should_vendor: bool, tmp_dir: Path) -> str:
    if should_vendor:
        # Even though we do not perform a "go mod download" when vendoring is detected, some
        # go commands still download dependencies as a side effect. Since we don't want those
        # copied to the output dir, we need to set the GOMODCACHE to a different directory.
        return f"{tmp_dir}/vendor-cache"
    return f"{tmp_dir}/pkg/mod"


def _prepare_run_params(
    request_flags: Iterable[str],
    should_vendor: bool,
    tmp_dir: Path,
    app_dir: RootedPath,
    temp_netrc_dir: Path,
) -> dict:
    config = get_config()
    gomod_cache = _determine_cache_path(should_vendor, tmp_dir)

    go_vars: dict[str, str] = {
        "GOPATH": str(tmp_dir),
        "GO111MODULE": "on",
        "GOCACHE": str(tmp_dir),
        "GOMODCACHE": gomod_cache,
        "GOSUMDB": "sum.golang.org",
        "GOTOOLCHAIN": "auto",
    }
    if config.gomod.proxy_url:
        log.info("Using registry proxy %s for registry dependencies", config.gomod.proxy_url)
        go_vars["GOPROXY"] = config.gomod.proxy_url

    if config.gomod.proxy_login is not None:
        # This is supposed to be happening only in systems utilizing artifact registry proxies.
        if "," in config.gomod.proxy_url:
            raise InvalidInput(
                "proxy_url must contain exactly one URL when login is present. "
                f"Contains now: {config.gomod.proxy_url}"
            )
        path_to_netrc = inject_netrc(prepare_netrc_contents(), temp_netrc_dir)
        go_vars["NETRC"] = path_to_netrc
        if os.environ.get("NETRC", ""):
            log.warning(
                "Proxy login was specified, at the same time a custom .netrc file path was"
                " provided via environment. A new .netrc will be generated from proxy"
                " parameters and will shadow the environment one. Please disable proxy"
                " support if you intend to use the .netrc from environment."
            )

    if "cgo-disable" in request_flags:
        go_vars["CGO_ENABLED"] = "0"

    env = _go_exec_env(**go_vars)
    run_params = {"env": env, "cwd": app_dir}

    return run_params


def _determine_which_modules_go_in_go_sum(
    app_dir: RootedPath,
    go_work: GoWork | None,
) -> frozenset[ModuleID]:
    if go_work:
        return _parse_go_sum_from_workspaces(go_work)
    return _parse_go_sum(app_dir.join_within_root("go.sum"))


def _acquire_modules(
    should_vendor: bool, go: Go, app_dir: RootedPath, go_work: GoWork | None, run_params: dict
) -> Iterable[ParsedModule]:
    # Vendor dependencies if the gomod-vendor flag is set
    if should_vendor:
        return _vendor_deps(go, app_dir, bool(go_work), run_params)
    log.info("Downloading the gomod dependencies")
    json_stream = go(["mod", "download", "-json"], run_params, retry=True)
    return (ParsedModule.model_validate(obj) for obj in load_json_stream(json_stream))


def _resolve_gomod(
    app_dir: RootedPath,
    request: Request,
    tmp_dir: Path,
    go: Go,
    go_work: GoWork | None,
) -> ResolvedGoModule:
    """
    Resolve and fetch gomod dependencies for given app source archive.

    :param go: Go instance/release to use for processing the request
    :param app_dir: the full path to the application source code
    :param request: app request this is for
    :param tmp_dir: one temporary directory for all go modules
    :return: a dict containing the Go module itself ("module" key), the list of dictionaries
        representing the dependencies ("module_deps" key), the top package level dependency
        ("pkg" key), and a list of dictionaries representing the package level dependencies
        ("pkg_deps" key)
    :raises PackageManagerError: if fetching dependencies fails
    """
    _protect_against_symlinks(app_dir)
    should_vendor = app_dir.join_within_root("vendor").path.is_dir()

    with TemporaryDirectory() as temp_netrc_dir:
        run_params = _prepare_run_params(
            request.flags, should_vendor, tmp_dir, app_dir, Path(temp_netrc_dir)
        )

        # Explicitly disable toolchain telemetry for go >= 1.23
        _disable_telemetry(go, run_params)
        modules_in_go_sum = _determine_which_modules_go_in_go_sum(app_dir, go_work)
        downloaded_modules = _acquire_modules(should_vendor, go, app_dir, go_work, run_params)

        main_module, workspace_modules = _parse_local_modules(go_work, go, run_params, app_dir)

        deps = _go_list_deps(go, "all", run_params)
        package_modules = [pkg.module for pkg in deps if pkg.module and not pkg.module.main]
        package_modules.extend(workspace_modules)
        all_modules = _deduplicate_resolved_modules(package_modules, downloaded_modules)
        all_modules = _normalize_local_replacements(all_modules, app_dir, go_work)

        log.info("Retrieving the list of packages")
        all_packages = _parse_packages(go_work, go, run_params)

    return ResolvedGoModule(main_module, all_modules, all_packages, modules_in_go_sum)


def _parse_local_modules(
    go_work: GoWork | None,
    go: Go,
    run_params: dict[str, Any],
    app_dir: RootedPath,
) -> tuple[ParsedModule, list[ParsedModule]]:
    """
    Identify and parse the main module and all workspace modules, if they exist.

    :return: A tuple containing the main module and a list of workspaces
    """
    workspace_modules = []
    modules_json_stream = go(["list", "-e", "-m", "-json"], run_params).rstrip()
    main_module_dict, workspace_dict_list = _process_modules_json_stream(
        app_dir, modules_json_stream
    )

    main_module = ParsedModule(
        path=main_module_dict["Path"],
        main=True,
        local_path=app_dir.join_within_root(main_module_dict["Dir"]),
    )

    if go_work is not None:
        source_dir = RootedPath(app_dir.root)
        workspace_modules = [_parse_workspace_module(source_dir, ws) for ws in workspace_dict_list]
    return main_module, workspace_modules


def _process_modules_json_stream(
    app_dir: RootedPath, modules_json_stream: str
) -> tuple[ModuleDict, list[ModuleDict]]:
    """Process the json stream returned by "go list -m -json".

    The stream will contain the module currently being processed, or a list of all workspaces in
    case a go.work file is present in the repository.

    :param app_dir: the path to the module directory
    :param modules_json_stream: the json stream returned by "go list -m -json"
    :return: A tuple containing the main module and a list of workspaces
    """
    module_list = []
    main_module = None

    for module in load_json_stream(modules_json_stream):
        if module["Dir"] == str(app_dir):
            main_module = module
        else:
            module_list.append(module)

    # should never happen, since the main module will always be a part of the json stream
    if not main_module:
        raise RuntimeError('Failed to find the main module info in the "go list -m -json" output.')

    return main_module, module_list


def _parse_workspace_module(source_dir: RootedPath, module: ModuleDict) -> ParsedModule:
    """Create a ParsedModule for a workspace member within the request source."""
    return ParsedModule(
        path=module["Path"],
        local_path=source_dir.join_within_root(module["Dir"]),
    )


def _parse_go_sum_from_workspaces(
    go_work: GoWork,
) -> frozenset[ModuleID]:
    """Return the set of modules present in all go.sum files across the existing workspaces."""
    go_sum_files = _get_go_sum_files(go_work)

    modules: frozenset[ModuleID] = frozenset()

    for go_sum_file in go_sum_files:
        modules = modules | _parse_go_sum(go_sum_file)

    return modules


def _get_go_sum_files(
    go_work: GoWork,
) -> list[RootedPath]:
    """Find all go.sum files present in the related workspaces."""
    go_work_rooted = go_work.rooted_path
    go_sums = [go_work_rooted.join_within_root(wp / "go.sum") for wp in go_work.workspace_paths]
    go_sums.append(go_work_rooted.join_within_root(go_work.path.parent / "go.work.sum"))

    return go_sums


def _parse_go_sum(go_sum: RootedPath) -> frozenset[ModuleID]:
    """Return the set of modules present in the specified go.sum file.

    A module is considered present if the checksum for its .zip file is present. The go.mod file
    checksums are not relevant for our purposes.
    """
    if not go_sum.path.exists():
        return frozenset()

    modules: list[ModuleID] = []

    # https://github.com/golang/go/blob/d5c5808534f0ad97333b1fd5fff81998f44986fe/src/cmd/go/internal/modfetch/fetch.go#L507-L534
    lines = go_sum.path.read_text().splitlines()
    for i, go_sum_line in enumerate(lines):
        parts = go_sum_line.split()
        if not parts:
            continue
        if len(parts) != 3:
            # https://github.com/golang/go/issues/62345
            # replicate the bug here, because it means that go only uses the non-broken part
            #   of go.sum for checksum verification
            log.warning(
                "%s:%d: malformed line, skipping the rest of the file: %r",
                go_sum.subpath_from_root,
                i + 1,
                go_sum_line,
            )
            break

        name, version, _ = parts
        if Path(version).name == "go.mod":
            continue

        modules.append((name, version))

    return frozenset(modules)


def _deduplicate_resolved_modules(
    package_modules: Iterable[ParsedModule],
    downloaded_modules: Iterable[ParsedModule],
) -> Iterable[ParsedModule]:
    modules_by_name_and_version: dict[ModuleID, ParsedModule] = {}

    # package_modules have the replace data, so they should take precedence in the deduplication
    for module in chain(package_modules, downloaded_modules):
        # get the module for this name+version or create a new one
        modules_by_name_and_version.setdefault(_get_module_id(module), module)

    return modules_by_name_and_version.values()


class GoCacheTemporaryDirectory(tempfile.TemporaryDirectory):
    """
    A wrapper around the TemporaryDirectory context manager to also run `go clean -modcache`.

    The files in the Go cache are read-only by default and cause the default clean up behavior of
    tempfile.TemporaryDirectory to fail with a permission error. A way around this is to run
    `go clean -modcache` before the default clean up behavior is run.
    """

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize our TemporaryDirectory context manager wrapper.

        Store the Go toolchain version used in this session for the subsequent cleanup.
        """
        super().__init__(*args, **kwargs)
        # store the exact toolchain instance that was used for all actions within the context
        self._go_instance: Go | None = None

    def __enter__(self) -> "Self":
        super().__enter__()
        return self

    def __exit__(
        self,
        exc: type[BaseException] | None,
        value: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Clean up the temporary directory by first cleaning up the Go cache."""
        try:
            if go := self._go_instance:
                _clean_go_modcache(go, self.name)
        finally:
            super().__exit__(exc, value, tb)


def _normalize_local_replacements(
    modules: Iterable[ParsedModule], app_dir: RootedPath, go_work: GoWork | None = None
) -> list[ParsedModule]:
    """Attach validated source directories to local replacements."""
    replacement_base = (
        app_dir.join_within_root(go_work.path.parent) if go_work is not None else app_dir
    )
    normalized_modules = []
    for module in modules:
        if (replacement := module.replace) is not None and replacement.version is None:
            # Go reports an absolute Dir; vendor/modules.txt only has a replacement path.
            # In workspace mode, Go rebases relative replacements to the go.work directory,
            # including those originally declared in a workspace member's go.mod.
            local_path = replacement_base.join_within_root(replacement.dir or replacement.path)
            module = module.model_copy(update={"local_path": local_path})
        normalized_modules.append(module)
    return normalized_modules


def _parse_vendor(context_dir: RootedPath) -> Iterable[ParsedModule]:
    """Parse modules from vendor/modules.txt."""
    modules_txt = context_dir.join_within_root("vendor", "modules.txt")
    if not modules_txt.path.exists():
        return []

    def fail_for_unexpected_format(msg: str) -> NoReturn:
        solution = (
            "Does `go mod vendor` make any changes to modules.txt?\n"
            f"If not, please let the maintainers know that {APP_NAME} fails to parse valid modules.txt"
        )
        raise UnexpectedFormat(f"vendor/modules.txt: {msg}", solution=solution)

    def parse_module_line(line: str) -> ParsedModule:
        parts = line.removeprefix("# ").split()
        # name version
        if len(parts) == 2:
            name, version = parts
            return ParsedModule(path=name, version=version)
        # name => path
        if len(parts) == 3 and parts[1] == "=>":
            name, _, path = parts
            return ParsedModule(path=name, replace=ParsedModule(path=path))
        # name => new_name new_version
        if len(parts) == 4 and parts[1] == "=>":
            name, _, new_name, new_version = parts
            return ParsedModule(path=name, replace=ParsedModule(path=new_name, version=new_version))
        # name version => path
        if len(parts) == 4 and parts[2] == "=>":
            name, version, _, path = parts
            return ParsedModule(path=name, version=version, replace=ParsedModule(path=path))
        # name version => new_name new_version
        if len(parts) == 5 and parts[2] == "=>":
            name, version, _, new_name, new_version = parts
            return ParsedModule(
                path=name,
                version=version,
                replace=ParsedModule(path=new_name, version=new_version),
            )
        fail_for_unexpected_format(f"unexpected module line format: {line!r}")

    modules: list[ParsedModule] = []
    module_has_packages: list[bool] = []

    for line in modules_txt.path.read_text().splitlines():
        if line.startswith("# "):  # module line
            modules.append(parse_module_line(line))
            module_has_packages.append(False)
        elif not line.startswith("#"):  # package line
            if not modules:
                fail_for_unexpected_format(f"package has no parent module: {line}")
            module_has_packages[-1] = True
        elif not line.startswith("##"):  # marker line
            fail_for_unexpected_format(f"unexpected format: {line!r}")

    return (module for module, has_packages in zip(modules, module_has_packages) if has_packages)


def _vendor_deps(
    go: Go,
    context_dir: RootedPath,
    has_workspace: bool,
    run_params: dict[str, Any],
) -> Iterable[ParsedModule]:
    """
    Vendor golang dependencies.

    Application checks the vendor directory for updated content, failing if Go'd be to make any
    changes.

    :param app_dir: path to the module directory
    :param run_params: common params for the subprocess calls to `go`
    :param has_workspace: whether we detected Go workspaces in the repo (affects @context_dir)
    :return: the list of Go modules parsed from vendor/modules.txt
    :raise PackageRejected: if vendor directory changed
    :raise UnexpectedFormat: if application fails to parse vendor/modules.txt
    """
    log.info("Vendoring the gomod dependencies")
    cmdscope = "work" if has_workspace else "mod"
    go([cmdscope, "vendor"], run_params)
    return _parse_vendor(context_dir)


def _vendor_change_list(context_dir: RootedPath) -> git.DiffIndex[git.Diff] | list:
    """Check for changes in the vendor directory.

    :param context_dir: main module dir OR workspace context (directory containing go.work)
    :return: list of Diff objects representing detected changes (empty if no changes)
    """
    repo_root = context_dir.root

    # Get the correct repo context (main or submodule)
    repo, context_relative_path = get_repo_for_path(repo_root, context_dir.path)

    # Calculate vendor paths relative to the active repo
    vendor = context_relative_path / "vendor"
    modules_txt = vendor / "modules.txt"

    try:
        # Add untracked files but do not stage them
        repo.git.add("--intent-to-add", "--force", "--", context_relative_path)
        # Structured Diff objects
        index = repo.index
        modules_txt_diffs = index.diff(None, paths=[str(modules_txt)], env=GIT_PRISTINE_ENV)

        if modules_txt_diffs:
            return modules_txt_diffs

        vendor_diffs = index.diff(None, paths=[str(vendor)], env=GIT_PRISTINE_ENV)

        if vendor_diffs:
            return vendor_diffs

    finally:
        repo.git.reset("--", context_relative_path)

    return []


def prepare_netrc_contents() -> str:
    """Prepare .netrc contents."""
    config = get_config()
    # It should be `machine foo.bar.baz` in netrc, but is
    # set to https://foo.bar.baz/repository/go-proxy/ via a variable.
    # Another thing to note: go mod allows specifying multiple proxy URLs by
    # separating them with commas. This routine, however, is supposed to be
    # used in an artifact registry proxy path. Such a proxy should exist as a
    # uniquely addressable entity, having any backups here would jeopardize
    # fetch integrity.
    machine = urllib.parse.urlparse(config.gomod.proxy_url).netloc
    password = config.gomod.proxy_password
    secret = password.get_secret_value() if password is not None else ""
    return f"""machine {machine}
        login {config.gomod.proxy_login}
        password {secret}"""


def _write_file_with_mode(path: Path, content: str, mode: int) -> None:
    """Write content to a file with explicit permissions, bypassing umask."""
    old_mask = os.umask(0)
    try:
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
        with open(fd, "w") as f:
            f.write(content)
    finally:
        os.umask(old_mask)


def inject_netrc(netrc_stuff: str, temp_netrc_dir: Path) -> str:
    """Inject a temporary .netrc."""
    netrc = temp_netrc_dir / ".netrc"
    _write_file_with_mode(netrc, netrc_stuff, 0o600)
    return str(netrc)
