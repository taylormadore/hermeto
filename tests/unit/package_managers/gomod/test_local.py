# SPDX-License-Identifier: GPL-3.0-only
from pathlib import Path
from unittest import mock

import git
import pytest

from hermeto.core.errors import FetchError
from hermeto.core.package_managers.gomod.local import (
    LocalModuleResolver,
    _ModuleVersionResolver,
)
from hermeto.core.rooted_path import RootedPath
from hermeto.core.scm import GitRepo
from hermeto.core.utils import GIT_PRISTINE_ENV


@pytest.mark.parametrize(
    "module_suffix, ref, expected, subpath",
    (
        # First commit with no tag
        (
            "",
            "78510c591e2be635b010a52a7048b562bad855a3",
            "v0.0.0-20191107200220-78510c591e2b",
            None,
        ),
        # No prior tag at all
        (
            "",
            "5a6e50a1f0e3ce42959d98b3c3a2619cb2516531",
            "v0.0.0-20191107202433-5a6e50a1f0e3",
            None,
        ),
        # Only a non-semver tag (v1)
        (
            "",
            "7911d393ab186f8464884870fcd0213c36ecccaf",
            "v0.0.0-20191107202444-7911d393ab18",
            None,
        ),
        # Directly maps to a semver tag (v1.0.0)
        ("", "d1b74311a7bf590843f3b58bf59ab047a6f771ae", "v1.0.0", None),
        # One commit after a semver tag (v1.0.0)
        (
            "",
            "e92462c73bbaa21540f7385e90cb08749091b66f",
            "v1.0.1-0.20191107202936-e92462c73bba",
            None,
        ),
        # A semver tag (v2.0.0) without the corresponding go.mod bump, which happens after a v1.0.0
        # semver tag
        (
            "",
            "61fe6324077c795fc81b602ee27decdf4a4cf908",
            "v1.0.1-0.20191107202953-61fe6324077c",
            None,
        ),
        # A semver tag (v2.1.0) after the go.mod file was bumped
        ("/v2", "39006a0b5b0654a299cc43f71e0dc1aa50c2bc72", "v2.1.0", None),
        # A pre-release semver tag (v2.2.0-alpha)
        ("/v2", "0b3468852566617379215319c0f4dfe7f5948a8f", "v2.2.0-alpha", None),
        # Two commits after a pre-release semver tag (v2.2.0-alpha)
        (
            "/v2",
            "863073fae6efd5e04bb972a05db0b0706ec8276e",
            "v2.2.0-alpha.0.20191107204050-863073fae6ef",
            None,
        ),
        # Directly maps to a semver non-annotated tag (v2.2.0)
        ("/v2", "709b220511038f443fe1b26ac09c3e6c06c9f7c7", "v2.2.0", None),
        # A non-semver tag (random-tag)
        (
            "/v2",
            "37cea8ddd9e6b6b81c7cfbc3223ce243c078388a",
            "v2.2.1-0.20191107204245-37cea8ddd9e6",
            None,
        ),
        # The go.mod file is bumped but there is no versioned commit
        (
            "/v2",
            "6c7249e8c989852f2a0ee0900378d55d8e1d7fe0",
            "v2.0.0-20191108212303-6c7249e8c989",
            None,
        ),
        # Three semver annotated tags on the same commit
        ("/v2", "a77e08ced4d6ae7d9255a1a2e85bd3a388e61181", "v2.2.5", None),
        # A non-annotated semver tag and an annotated semver tag
        ("/v2", "bf2707576336626c8bbe4955dadf1916225a6a60", "v2.3.3", None),
        # Two non-annotated semver tags
        ("/v2", "729d0e6d60317bae10a71fcfc81af69a0f6c07be", "v2.4.1", None),
        # Two semver tags, with one having the wrong major version and the other with the correct
        # major version
        ("/v2", "3decd63971ed53a5b7ff7b2ca1e75f3915e99cf2", "v2.5.0", None),
        # A semver tag that is incorrectly lower then the preceding semver tag
        ("/v2", "0dd249ad59176fee9b5451c2f91cc859e5ddbf45", "v2.0.1", None),
        # A commit after the incorrect lower semver tag
        (
            "/v2",
            "2883f3ddbbc811b112ff1fe51ba2ee7596ddbf24",
            "v2.5.1-0.20191118190931-2883f3ddbbc8",
            None,
        ),
        # Newest semver tag is applied to a submodule, but the root module is being processed
        (
            "/v2",
            "f3ee3a4a394fb44b055ed5710b8145e6e98c0d55",
            "v2.5.1-0.20211209210936-f3ee3a4a394f",
            None,
        ),
        # Submodule has a semver tag applied to it
        ("/v2", "f3ee3a4a394fb44b055ed5710b8145e6e98c0d55", "v2.5.1", "submodule"),
        # A commit after a submodule tag
        (
            "/v2",
            "cc6c9f554c0982786ff9e077c2b37c178e46828c",
            "v2.5.2-0.20211223131312-cc6c9f554c09",
            "submodule",
        ),
        # A commit with multiple tags in different submodules
        ("/v2", "5401bdd8a8ebfcccd2eea9451d407a5fdae6fc76", "v2.5.3", "submodule"),
        # Malformed semver tag, root module being processed
        ("/v2", "4a481f0bae82adef3ea6eae3d167af6e74499cb2", "v2.6.0", None),
        # Malformed semver tag, submodule being processed
        ("/v2", "4a481f0bae82adef3ea6eae3d167af6e74499cb2", "v2.6.0", "submodule"),
    ),
)
def test_get_golang_version(
    golang_repo_path: Path,
    module_suffix: str,
    ref: str,
    expected: str,
    subpath: str | None,
) -> None:
    module_name = f"github.com/mprahl/test-golang-pseudo-versions{module_suffix}"

    module_dir = RootedPath(golang_repo_path)
    repo = GitRepo(golang_repo_path)
    repo.git.checkout(ref)
    version_resolver = _ModuleVersionResolver(repo, repo.commit(ref))

    if subpath:
        module_dir = module_dir.join_within_root(subpath)

    version = version_resolver.get_golang_version(module_name, module_dir)
    assert version == expected


@pytest.fixture
def repo_remote_with_tag(rooted_tmp_path: RootedPath) -> tuple[RootedPath, RootedPath]:
    """
    Return the Paths to two Repos, with the first configured as the remote of the second.

    There are different git tags applied to the first and second commits of the README file
    """
    local_repo_path = rooted_tmp_path.join_within_root("local")
    remote_repo_path = rooted_tmp_path.join_within_root("remote")
    readme_file_path = remote_repo_path.join_within_root("README.md")

    local_repo_path.path.mkdir()
    remote_repo_path.path.mkdir()
    remote_repo = git.Repo.init(remote_repo_path)

    with open(readme_file_path, "wb"):
        pass
    remote_repo.index.add([readme_file_path])
    initial_commit = remote_repo.index.commit("Add README")

    with open(readme_file_path, "w") as f:
        f.write("This is a README")
    remote_repo.index.add([readme_file_path])
    remote_repo.index.commit("Update README")

    git.Repo.clone_from(remote_repo_path, local_repo_path)

    remote_repo.create_tag("v1.0.0", ref=initial_commit, env=GIT_PRISTINE_ENV)
    remote_repo.create_tag("v2.0.0", env=GIT_PRISTINE_ENV)

    return remote_repo_path, local_repo_path


def test_fetch_tags(repo_remote_with_tag: tuple[RootedPath, RootedPath]) -> None:
    _, local_repo_path = repo_remote_with_tag
    assert git.Repo(local_repo_path).tags == []
    version_resolver = _ModuleVersionResolver.from_repo_path(local_repo_path)
    assert version_resolver._commit_tags == ["v2.0.0"]
    assert version_resolver._all_tags == ["v1.0.0", "v2.0.0"]


def test_fetch_tags_fail(repo_remote_with_tag: tuple[RootedPath, RootedPath]) -> None:
    # The remote_repo itself has no remote configured, so will fail when fetching tags
    remote_repo_path, _ = repo_remote_with_tag
    with pytest.raises(FetchError):
        _ModuleVersionResolver.from_repo_path(remote_repo_path)


@mock.patch.object(_ModuleVersionResolver, "from_repo_path")
def test_reuses_version_resolver_for_modules_in_same_repository(
    from_repo_path: mock.Mock,
    rooted_tmp_path_repo: RootedPath,
) -> None:
    repo = GitRepo(rooted_tmp_path_repo)
    repo.create_remote("origin", "https://example.com/example/repository.git")
    module_dirs = [
        rooted_tmp_path_repo.join_within_root("first"),
        rooted_tmp_path_repo.join_within_root("second"),
    ]
    for module_dir in module_dirs:
        module_dir.path.mkdir()

    version_resolver = mock.Mock(spec=_ModuleVersionResolver)
    version_resolver.get_golang_version.return_value = "v1.0.0"
    from_repo_path.return_value = version_resolver

    resolver = LocalModuleResolver(rooted_tmp_path_repo)
    resolver.resolve("example.com/first", module_dirs[0])
    resolver.resolve("example.com/second", module_dirs[1])

    from_repo_path.assert_called_once_with(rooted_tmp_path_repo)
