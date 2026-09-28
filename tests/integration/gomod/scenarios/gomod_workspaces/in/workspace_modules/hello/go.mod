module example.com/hello

go 1.20

require golang.org/x/example/hello v0.0.0-20231013143937-1d6d2400d402 // indirect

require (
	example.com/module-dep v1.0.0
	example.com/workspace-dep v1.0.0
)

replace example.com/module-dep => ../module-dep
