


import org.junit.Assert;

import java.util.regex.Pattern;

/**
 * Created by cheleb on 17/01/15.
 */
public class ReTest {

    @org.junit.Test
    public void test(){
        Pattern compile = Pattern.compile("[\\w0-9%!:]{3,}");
        Assert.assertTrue("OK", compile.matcher("O!sO").matches());
    }

}
