require("dotenv").config();
const express = require("express");
const app = express();

const methodOverride = require("method-override");

// 챗팅기능
const { createServer } = require("http");
const { Server } = require("socket.io");
const server = createServer(app);
const io = new Server(server);

// db 접속
const MongoStore = require("connect-mongo");
const { ObjectId } = require("mongodb");
let connectDB = require("./db.js");
let db;

const session = require("express-session");
const passport = require("passport");
const LocalStrategy = require("passport-local");

const bcrypt = require("bcrypt");

connectDB
  .then((client) => {
    db = client.db("forum");

    server.listen(process.env.PORT, () => {
      // DB접속 완료후 서버실행
      console.log(`http://localhost:3000`);
    });
  })
  .catch((err) => {
    console.log(err);
  });

app.use(express.static(__dirname + "/public"));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
// res.body 여기서 데이터 꺼내기 쉽게 처리를 해준다

const sessionOption = {
  secret: "secret-express-session",
  resave: false,
  saveUninitialized: false,
  cookie: { maxAge: 60 * 60 * 1000 }, // 1시간
  store: MongoStore.create({
    mongoUrl: process.env.URL,
    dbName: "forum",
  }),
};

app.use(passport.initialize());
app.use(session(sessionOption));
app.use(passport.session());

// 아이디, 비번 검사 (미들웨어)
passport.use(
  new LocalStrategy(
    { usernameField: "userid", passwordField: "password" },
    async (userid, password, cb) => {
      let result = await db.collection("user").findOne({ userid });

      if (!result) return cb(null, false, { message: "아이디 DB에 없음" });

      if (await bcrypt.compare(password, result.password))
        // 같으면 true
        return cb(null, result);
      else return cb(null, false, { message: "비번불일치" });
    }
  )
);

passport.serializeUser((user, done) => {
  process.nextTick(() => {
    done(null, { id: user._id, userid: user.userid });
  });
});

passport.deserializeUser(async (user, done) => {
  let result = await db
    .collection("user")
    .findOne({ _id: new ObjectId(user.id) });
  delete result.password; //password 프로퍼티 삭제
  process.nextTick(() => {
    return done(null, user);
  });
});

//--------------------------------------

app.get("/", (req, res) => {
  res.redirect("/list");
});

//--------------------------------------

app.get("/add", async (req, res) => {
  // 필드의 기본값 : username, password
  // 로그인하지 않으면 req.suer 자체가 없기 때문에 userid 값을 추출할수가 없음.. undefined
  // 로그인하면 어디에 값이 담기나? 로그인 안하면 어떤 값이 나올까?
  if (!req.user) {
    return res.send('<a href="/login">로그인</a> 해주세요');
  }
  res.render("write.ejs");
});

app.post("/add", async (req, res) => {
  const { title, content } = req.body;
  const { id, userid } = req.user;

  try {
    if (title == "") {
      res.send("제목이 없습니다");
    } else if (title.length > 20) {
      res.send("제목의 글자는 20글자 이하입니다");
    } else if (content == "") {
      res.send("내용이 없습니다");
    } else {
      let result = await db.collection("post").insertOne(
        {
          title,
          content,
          userNum: id,
          userid: userid,
        },
        (err, r) => {
          console.log("저장완료");
        }
      );
      res.redirect("/list");
    }
  } catch (err) {
    console.log(err);
    응답.send("DB에러남");
  }
});

// 수정기능

app.get("/edit/:id", async (req, res) => {
  const { id } = req.params;

  let result = await db.collection("post").findOne({ _id: new ObjectId(id) });

  res.render("edit.ejs", { result });
});

app.put("/edit", async (req, res) => {
  const { id, title, content } = req.body;

  // let result = await db.collection('post').updateOne({수정할부분},{$set : {덮어쓸 내용}})

  try {
    let result = await db
      .collection("post")
      .updateOne({ _id: new ObjectId(id) }, { $set: { title, content } });
    res.redirect(`/list`);
  } catch (error) {
    console.log(error);
  }
});

app.delete("/delete/:id", async (req, res) => {
  const post_id = req.params.id;
  const userNum = req.user.id;

  try {
    let result = await db.collection("post").deleteOne({
      _id: new ObjectId(post_id),
      userNum: userNum,
    });

    const { deletedCount } = result;

    if (deletedCount == 0) {
      return res.send("삭제 실패");
    }

    // fetch로 요청을 한경우에, 새로고침하지 않아야 되기 때문에
    // 서버에 render, redirect 사용x (새로고침함)
    res.send("삭제완료");
  } catch (error) {
    console.log(error);
  }
});

//--------------------------------------

app.get("/join", (req, res) => {
  res.render("join.ejs");
});

app.post("/join", async (req, res) => {
  const { userid, password } = req.body;
  let hash = await bcrypt.hash(password, 10);

  await db.collection("user").insertOne({
    userid,
    password: hash,
  });
  res.send("등록 성공");
});

//--------------------------------------

app.get("/login", (req, res) => {
  res.render("login.ejs");
});

app.post("/login", async (req, res, next) => {
  passport.authenticate("local", (error, user, info) => {
    if (error) return res.status(500).json(error);
    if (!user) return res.status(401).json(info.message);

    if (error) return next(err);

    req.login(user, (err) => {
      if (err) return next(err);
      res.redirect("/list");
    });
  })(req, res, next);
});

app.get("/logout", (req, res) => {
  req.logout(() => {
    res.redirect("/");
  });
});

//--------------------------------------

app.get("/list", async (req, res) => {
  const { title } = req.query;
  const loginUser = req.user ? req.user.userid : "unknown";

  // 타이틀이 포함된 것 찾기 - 정규식 활용
  if (title) {
    let result = await db
      .collection("post")
      .find({ title: { $regex: new RegExp(title) } })
      .toArray();
    res.render("list.ejs", { list: result });
  } else {
    let result = await db.collection("post").find().toArray();

    res.render("list.ejs", { list: result, loginUser });
  }
});

// 1개만 조회하기
app.get("/detail/:id", async (req, res) => {
  const { id } = req.params; // id는 어떤 id일까? post컬렉션의 _id = 게시물 번호
  const loginUser = req.user ? req.user.userid : "unknown";

  try {
    let result = await db.collection("post").findOne({ _id: new ObjectId(id) });
    let comment = await db
      .collection("comment")
      .find({ parentId: id })
      .toArray();
    // comment 컬렉션 - 게시물 번호가 저장되어 있는 필드 이름은? parentId
    // post에서 _id 검색 : new ObjectId() 사용하는데
    // comment에서 parentId 검색 : x   Q. 왜?  저장할 때 사용 안함

    if (result == null) {
      res.status(400).send("글을 찾을 수 없습니다");
    } else {
      res.render("detail.ejs", { result, comment, loginUser });
    }
  } catch (error) {
    res.send("오류");
  }
});

app.post("/comment", async (req, res) => {
  const { content, parentId } = req.body;

  const writerId = req.user.id;
  const writer = req.user.userid;

  let result = await db.collection("comment").insertOne({
    content,
    parentId, // post 컬렉션 _id =  게시글 번호
    writerId, // user 컬렉션 _id (현재 로그인 사용자)
    writer,
  });

  res.redirect("back"); // 이전페이지 돌아가기
});






// 챗팅방 개설하기
// 챗팅방이 없다면- 개설0 / 챗팅방 있다면 - 챗팅방 리스트 페이지로 이동
app.get("/chat/request", async (req, res) => {

  let result = await db
    .collection("chatroom")
    .find({
      member: { $all: [req.user.id, new ObjectId(req.query.writerId)] },
    })
    .toArray();


    if(result.length == 0){

      await db.collection('chatroom').insertOne({
        member : [req.user.id, new ObjectId(req.query.writerId)],
        date : new Date()
      })

    } 

  res.redirect("/chat/list");
  //res.redirect('챗팅방 목록 페이지 주소')
});

 
// 챗팅방 목록 보여주기
app.get("/chat/list", async (req, res) => {
  // 현재 로그인한 사용자의 챗팅방 목록 검색해서 출력한다
  let result = await db
    .collection("chatroom")
    .find({ member : req.user.id })
    .toArray();
  res.render("chatList.ejs", { result });
});



// 챗팅방 내용 확인하기
app.get("/chat/detail/:id", async (req, res) => {
  const { id } = req.params; 
  // 챗팅방 목록 번호 
  // chatRoom : _id
  // chatMessage : parentRoom

  // 챗팅방 정보
  let result = await db.collection("chatroom").findOne({ _id: new ObjectId(id) });

  // 챗팅방의 대화내용
  let chat = await db.collection("chatMessage").find({ parentRoom : id }).toArray();

    console.log(chat)

  res.render("chatDetail.ejs", { result, chat });
});


io.on('connection', (socket)=>{


  socket.on('ask-join', (data)=>{
    socket.join(data); // 접속
  })

  socket.on('message-send', async(data)=>{ //객체
    // db에 저장하는 역할

    await db.collection('chatMessage').insertOne({
      parentRoom : data.room ,
      content : data.msg
    })


    // 서버에서 클라이언트로 데이터 보낼때
    // 특정한 방번호에 메시지 보낸다
    io.to(data.room).emit('msg-broadcat', data.msg) // 변수 1개 값
  })


})






// 서버만 룸에 유저 넣는것 가능
// 유저는 서버에 부탁해야만 룸에 조인가능
// 유저들이 들어갈 수 있는 웹 소켓 방
// 한 유저는 여러 room 에 들어갈 수 있다
// 서버 -> room 에 속한 유저에게 메시지 전송 가능

// 어떤 유저가 서버로 메시지 보내면
// 서버는 그 메시지를 같은 룸에 속한 사람들에게 메시지를 모두 전송한다.
