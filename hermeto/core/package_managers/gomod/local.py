# SPDX-License-Identifier: GPL-3.0-only
import logging
import re
from datetime import datetime, timezone
from functools import cached_property
from pathlib import Path
from typing import TYPE_CHECKING, Any, NamedTuple

import git
import semver

from hermeto.core.config import get_config
from hermeto.core.constants import Mode
from hermeto.core.errors import FetchError, GitError, NotAGitRepo
from hermeto.core.rooted_path import RootedPath
from hermeto.core.scm import GitRepo, GitSourceLocation, get_repo_for_path, get_repo_id

if TYPE_CHECKING:
    from typing_extensions import Self

log = logging.getLogger(__name__)


class LocalModuleResolution(NamedTuple):
    """The version and Git source location resolved for a local Go module.

    The source is absent only for non-Git input accepted in permissive mode.
    """

    version: str
    source: GitSourceLocation | None


class _ModuleVersionResolver:
    """Resolves the versions of Go modules in a git repository."""

    _DUMMY_PSEUDO_VERSION = "v0.0.0-19700101000000-000000000000"

    def __init__(self, repo: GitRepo, commit: git.objects.commit.Commit):
        """Initialize a version resolver for the provided Repo."""
        self._repo = repo
        self._commit = commit

    @classmethod
    def from_repo_path(cls, repo_path: RootedPath) -> "Self":
        """Fetch tags from a git Repo and return a version resolver."""
        repo = GitRepo(repo_path)
        commit = repo.commit(repo.rev_parse("HEAD").hexsha)
        try:
            # Do not run 'git fetch --tags' because that fetches pretty much everything from the
            # remote. Save bandwidth and storage with an explicit refspec instead.
            # See man 1 git-fetch for the authoritative answer.
            repo.remote().fetch(refspec="+refs/tags/*:refs/tags/*", force=True)
        except GitError as ex:
            raise FetchError(
                f"Failed to fetch the tags on the Git repository ({type(ex).__name__}) "
                f"for {repo.working_tree_dir}: "
                f"{str(ex)}"
            )

        return cls(repo, commit)

    @classmethod
    def from_non_git_source(cls) -> "Self":
        """Return a resolver for non-git sources that produces a dummy pseudo-version."""
        resolver = cls.__new__(cls)
        resolver._repo = None  # type: ignore[assignment]
        resolver._commit = None  # type: ignore[assignment]
        return resolver

    @cached_property
    def _commit_tags(self) -> list[str]:
        """Return the git tags pointing to the current commit."""
        return self._get_commit_tags()

    @cached_property
    def _all_tags(self) -> list[str]:
        """Return all of the git tags pointing to the current and preceding commits."""
        return self._get_commit_tags(all_reachable=True)

    def _get_commit_tags(self, all_reachable: bool = False) -> list[str]:
        """
        Return all of the tags associated with the current commit.

        Note that we cannot simply run 'git describe SHA' here because that always only returns a
        single entry rather than multiple which may not be of the required semver format that we may
        have to filter further!

        :param all_reachable: True to get all tags on the current commit and all commits preceding
                              it. False to get the tags on the current commit only.
        :return: a list of tag names
        :raises GitError: if failed to fetch the tags on the Git repository
        """
        try:
            if all_reachable:
                # Get all the tags on the input commit and all that precede it.
                # This is based on:
                # https://github.com/golang/go/blob/0ac8739ad5394c3fe0420cf53232954fefb2418f/src/cmd/go/internal/modfetch/codehost/git.go#L659-L695
                cmd = [
                    "git",
                    "for-each-ref",
                    "--format",
                    "%(refname:lstrip=2)",
                    "refs/tags",
                    "--merged",
                    self._commit.hexsha,
                ]
            else:
                # Get the tags that point to this commit
                cmd = ["git", "tag", "--points-at", self._commit.hexsha]

            tag_names = self._repo.git.execute(
                cmd,
                # these args are the defaults, but are required to let mypy know which override to match
                # (the one that returns a string)
                with_extended_output=False,
                as_process=False,
                stdout_as_string=True,
            ).splitlines()
        except GitError:
            msg = f"Failed to get the tags associated with the reference {self._commit.hexsha}"
            log.error(msg)
            raise

        return tag_names

    def get_golang_version(
        self,
        module_name: str,
        app_dir: RootedPath,
    ) -> str:
        """
        Get the version of the Go module in the input Git repository in the same format as `go list`.

        If commit doesn't point to a commit with a semantically versioned tag, a pseudo-version
        will be returned.

        :param module_name: the Go module's name
        :param app_dir: the path to the module directory
        :return: a version as `go list` would provide
        """
        if self._repo is None or self._commit is None:
            return self._DUMMY_PSEUDO_VERSION

        # If the module is version v2 or higher, the major version of the module is included as /vN at
        # the end of the module path. If the module is version v0 or v1, the major version is omitted
        # from the module path.
        match = re.match(r"(?:.+/v)(?P<major_version>\d+)$", module_name)
        module_major_version = int(match.group("major_version")) if match else None

        # If no match, prefer v1.x.x tags but fallback to v0.x.x tags if both are present
        major_versions_to_try = (module_major_version,) if module_major_version else (1, 0)

        if app_dir.path == app_dir.root:
            subpath = None
        else:
            subpath = app_dir.path.relative_to(app_dir.root).as_posix()

        tag_on_commit = self._get_highest_semver_tag_on_current_commit(
            major_versions_to_try, subpath
        )
        if tag_on_commit:
            return tag_on_commit

        log.debug("No semantic version tag was found on the commit %s", self._commit.hexsha)
        pseudo_version = self._get_highest_reachable_semver_tag(major_versions_to_try, subpath)
        if pseudo_version:
            return pseudo_version

        log.debug("No valid semantic version tag was found")
        # Fall-back to a vX.0.0-yyyymmddhhmmss-abcdefabcdef pseudo-version
        return self._get_golang_pseudo_version(
            module_major_version=module_major_version, subpath=subpath
        )

    def _get_highest_semver_tag_on_current_commit(
        self, major_versions_to_try: tuple[int, ...], subpath: str | None
    ) -> str | None:
        """Return the highest semver tag on the current commit."""
        for major_version in major_versions_to_try:
            # Get the highest semantic version tag on the commit with a matching major version
            tag_on_commit = self._get_highest_semver_tag(major_version, subpath=subpath)
            if not tag_on_commit:
                continue

            log.debug(
                "Using the semantic version tag of %s for commit %s",
                tag_on_commit.name,
                self._commit.hexsha,
            )

            # We want to preserve the version in the "v0.0.0" format, so the subpath is not needed
            return (
                tag_on_commit.name if not subpath else tag_on_commit.name.replace(f"{subpath}/", "")
            )

        return None

    def _get_highest_reachable_semver_tag(
        self, major_versions_to_try: tuple[int, ...], subpath: str | None
    ) -> str | None:
        """Return the pseudo-version using the highest reachable semver tag as a base."""
        # This logic is based on:
        # https://github.com/golang/go/blob/a23f9afd9899160b525dbc10d01045d9a3f072a0/src/cmd/go/internal/modfetch/coderepo.go#L511-L521
        for major_version in major_versions_to_try:
            # Get the highest semantic version tag before the commit with a matching major version
            pseudo_base_tag = self._get_highest_semver_tag(
                major_version, all_reachable=True, subpath=subpath
            )
            if not pseudo_base_tag:
                continue

            log.debug(
                "Using the semantic version tag of %s as the pseudo-base for the commit %s",
                pseudo_base_tag.name,
                self._commit.hexsha,
            )
            pseudo_version = self._get_golang_pseudo_version(
                pseudo_base_tag, major_version, subpath=subpath
            )
            log.debug(
                "Using the pseudo-version %s for the commit %s", pseudo_version, self._commit.hexsha
            )
            return pseudo_version

        return None

    def _get_highest_semver_tag(
        self,
        major_version: int,
        all_reachable: bool = False,
        subpath: str | None = None,
    ) -> git.Tag | None:
        """
        Get the highest semantic version tag related to the input commit.

        :param major_version: the major version of the Go module as in the go.mod file to use as a
            filter for major version tags
        :param all_reachable: if False, the search is constrained to the input commit. If True,
            then the search is constrained to the input commit and preceding commits.
        :param subpath: path to the module, relative to the root repository folder
        :return: the highest semantic version tag if one is found
        """
        tag_names = self._all_tags if all_reachable else self._commit_tags

        # Keep only semantic version tags related to the path being processed
        prefix = f"{subpath}/v" if subpath else "v"
        filtered_tags = [tag_name for tag_name in tag_names if tag_name.startswith(prefix)]

        not_semver_tag_msg = "%s is not a semantic version tag"
        highest: dict[str, Any] | None = None

        for tag_name in filtered_tags:
            try:
                semantic_version = self._get_semantic_version_from_tag(tag_name, subpath)
            except ValueError:
                log.debug(not_semver_tag_msg, tag_name)
                continue

            # If the major version of the semantic version tag doesn't match the Go module's major
            # version, then ignore it
            if semantic_version.major != major_version:
                continue

            if highest is None or semantic_version > highest["semver"]:
                highest = {"tag": tag_name, "semver": semantic_version}

        if highest:
            return self._repo.tags[highest["tag"]]

        return None

    def _get_golang_pseudo_version(
        self,
        tag: git.Tag | None = None,
        module_major_version: int | None = None,
        subpath: str | None = None,
    ) -> str:
        """
        Get the Go module's pseudo-version when a non-version commit is used.

        For a description of the algorithm, see https://tip.golang.org/cmd/go/#hdr-Pseudo_versions.

        :param tag: the highest semantic version tag with a matching major version before the
            input commit. If this isn't specified, it is assumed there was no previous valid tag.
        :param module_major_version: the Go module's major version as stated in its go.mod file. If
            this and "tag" are not provided, 0 is assumed.
        :param subpath: path to the module, relative to the root repository folder
        :return: the Go module's pseudo-version as returned by `go list`
        :rtype: str
        """
        # Use this instead of commit.committed_datetime so that the datetime object is UTC
        committed_dt = datetime.fromtimestamp(self._commit.committed_date, timezone.utc)
        commit_timestamp = committed_dt.strftime(r"%Y%m%d%H%M%S")
        commit_hash = self._commit.hexsha[0:12]

        # vX.0.0-yyyymmddhhmmss-abcdefabcdef is used when there is no earlier versioned commit with an
        # appropriate major version before the target commit
        if tag is None:
            # If the major version isn't in the import path and there is not a versioned commit with the
            # version of 1, the major version defaults to 0.
            return f"v{module_major_version or '0'}.0.0-{commit_timestamp}-{commit_hash}"

        tag_semantic_version = self._get_semantic_version_from_tag(tag.name, subpath)

        # An example of a semantic version with a prerelease is v2.2.0-alpha
        if tag_semantic_version.prerelease:
            # vX.Y.Z-pre.0.yyyymmddhhmmss-abcdefabcdef is used when the most recent versioned commit
            # before the target commit is vX.Y.Z-pre
            version_seperator = "."
            pseudo_semantic_version = tag_semantic_version
        else:
            # vX.Y.(Z+1)-0.yyyymmddhhmmss-abcdefabcdef is used when the most recent versioned commit
            # before the target commit is vX.Y.Z
            version_seperator = "-"
            pseudo_semantic_version = tag_semantic_version.bump_patch()

        return f"v{pseudo_semantic_version}{version_seperator}0.{commit_timestamp}-{commit_hash}"

    @staticmethod
    def _get_semantic_version_from_tag(
        tag_name: str, subpath: str | None = None
    ) -> semver.version.Version:
        """
        Parse a version tag to a semantic version.

        A Go version follows the format "v0.0.0", but it needs to have the "v" removed in
        order to be properly parsed by the semver library.

        In case `subpath` is defined, it will be removed from the tag_name, e.g. `subpath/v0.1.0`
        will be parsed as `0.1.0`.

        :param tag_name: tag to be converted into a semver object
        :param subpath: path to the module, relative to the root repository folder
        """
        if subpath:
            semantic_version = tag_name.replace(f"{subpath}/v", "")
        else:
            semantic_version = tag_name[1:]

        return semver.version.Version.parse(semantic_version)


class LocalModuleResolver:
    """Resolve versions and repository locations for modules in a request source tree."""

    def __init__(self, source_dir: RootedPath) -> None:
        """Initialize a resolver for the source tree in a request."""
        self._source_dir = source_dir
        self._version_resolvers: dict[Path, _ModuleVersionResolver] = {}

    def resolve(
        self,
        module_path: str,
        module_dir: RootedPath,
    ) -> LocalModuleResolution:
        """Resolve the version and provenance of a local module."""
        source_module_dir = self._source_dir.join_within_root(module_dir.path)

        non_git_resolver = self._non_git_version_resolver
        if non_git_resolver is not None:
            version = non_git_resolver.get_golang_version(
                module_path,
                source_module_dir,
            )
            return LocalModuleResolution(version, None)

        repo, repo_relative_path = get_repo_for_path(
            self._source_dir.path,
            source_module_dir.path,
        )
        repo_root = RootedPath(repo.working_dir)
        source_path = repo_root.join_within_root(repo_relative_path)
        version_resolver = self._get_version_resolver(repo_root)
        version = version_resolver.get_golang_version(module_path, source_path)
        source = GitSourceLocation(get_repo_id(repo), source_path)
        return LocalModuleResolution(version, source)

    @cached_property
    def _non_git_version_resolver(self) -> _ModuleVersionResolver | None:
        """Return a version resolver when the request source is not a Git repository."""
        try:
            GitRepo(self._source_dir.path)
        except NotAGitRepo:
            if get_config().mode != Mode.PERMISSIVE:
                raise
            return _ModuleVersionResolver.from_non_git_source()
        return None

    def _get_version_resolver(self, repo_root: RootedPath) -> _ModuleVersionResolver:
        """Return the cached version resolver for a repository, creating it if needed."""
        version_resolver = self._version_resolvers.get(repo_root.path)
        if version_resolver is None:
            version_resolver = _ModuleVersionResolver.from_repo_path(repo_root)
            self._version_resolvers[repo_root.path] = version_resolver
        return version_resolver
