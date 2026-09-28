package main

import (
    "fmt"

    "example.com/module-dep"
    "example.com/workspace-dep"
    "golang.org/x/example/hello/reverse"
)

func main() {
    fmt.Println(reverse.String("Hello"))
    fmt.Println(moduledep.Message + workspacedep.Message)
}
