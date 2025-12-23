package main

import (
    "fmt"
    "os"
)

func main() {
    for _, kv := range os.Environ() {
        fmt.Println(kv)
    }
}
