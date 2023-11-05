# peparser

```kotlin
fun main() {
    PEFile.open(File("/the/path/to/pe.exe")).use { f: PEFile ->
        println(f.sections)
        println(f.coffHeader)
        println(f.resourceTree)
    }
}
```
