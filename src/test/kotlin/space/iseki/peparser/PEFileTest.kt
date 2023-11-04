package space.iseki.peparser

import org.junit.jupiter.api.Test
import kotlin.io.path.createTempFile;
import kotlin.io.path.outputStream
import kotlin.test.assertNotEquals

class PEFileTest {

    val testcasePath = createTempFile()
    init {
        this::class.java.getResourceAsStream("ScreenOff 2.1.exe").use { input->
            testcasePath.outputStream().use { out->input.copyTo(out) }
        }
    }
    @Test
    fun test(){
        PEFile.open(testcasePath.toFile()).use { f->
            println(f.sections)
            println(f.coffHeader)
            println(f.resourceTree)
            assertNotEquals(0, f.resourceTree.size)
            assertNotEquals(0, f.sections.size)
        }
    }
}