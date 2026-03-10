require('dotenv').config(); // .env 파일을 읽어오기 위해 최상단에 추가
const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
// .env에 설정된 포트를 쓰되, 없으면 3000번 사용
const PORT = process.env.PORT || 3000;
const SECRET_KEY = process.env.SECRET_KEY || "fallback-secret";

app.use(express.json());
app.use(cookieParser());
app.use(express.static('views'));

// [1] 로그인: 일반 학생용 토큰 발급
app.post('/login', (req, res) => {
    const { username } = req.body;
    const payload = {
        user: username || "guest",
        role: "student",
        bus_type: "regular_bus"
    };

    // 정상적인 토큰 발급 (HS256 사용)
    const token = jwt.sign(payload, SECRET_KEY, { algorithm: 'HS256' });
    res.cookie('auth_token', token);
    res.json({ message: "로그인 성공! 통학 버스 시스템에 접속했습니다." });
});

// [2] 검증 로직: 친구들이 공략해야 할 포인트
app.get('/board', (req, res) => {
    const token = req.cookies.auth_token;

    if (!token) return res.status(401).send("티켓(JWT)이 없습니다.");

    try {
        // 취약점: 서명 검증 없이 헤더와 페이로드를 먼저 읽음
        const decoded = jwt.decode(token, { complete: true });
        
        if (!decoded || !decoded.header) {
            return res.status(400).send("잘못된 토큰 형식입니다.");
        }

        // [공격 포인트] alg가 'none'이면 서명 검증을 패스함
        if (decoded.header.alg === 'none') {
            const payload = decoded.payload;
            
            // 관리자 권한과 급행 버스 타입을 모두 만족해야 함
            if (payload.role === 'admin' && payload.bus_type === 'express_home') {
                return res.json({ 
                    success: true, 
                    msg: "프리미엄 급행 버스 탑승 성공! 정답을 획득했습니다.",
                    // 코드를 봐도 FLAG 변수명만 보일 뿐, 실제 값은 알 수 없음
                    flag: process.env.FLAG 
                });
            } else {
                return res.json({ success: false, msg: "권한이 부족합니다. 관리자 계정만 급행을 탈 수 있습니다." });
            }
        } 

        // 일반적인 서명 검증 로직
        jwt.verify(token, SECRET_KEY, (err, verified) => {
            if (err) return res.status(403).send("위조된 티켓입니다! 서명이 일치하지 않습니다.");
            res.json({ success: false, msg: "일반 버스에 탑승 중입니다... (급행으로 갈아타야 합니다!)" });
        });

    } catch (e) {
        res.status(500).send("서버 내부 오류");
    }
});

app.listen(PORT, () => {
    console.log(`[Incognito CTF] 서버 가동 중: http://localhost:${PORT}`);
});
