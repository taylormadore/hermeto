# Integration test with workspace

This branch covers testing with go workspace. 

* workspace is using 3 modules
* module example.com/hello depends on example.com/hiii
* module example.com/hiii has its root 2 levels below the workspace root
* go.work is not in a root directory but one level below
* checksums from echo/go.sum were removed for github.com/davecgh/go-spew and gopkg.in/yaml.v3 packages to check missing_hash property
* local dependencies are replaced from both go.work and hello/go.mod
* directory-qualified version tags distinguish the replacement modules and check their provenance

