const express = require('express');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const path = require('path');

const app = express();
const PORT = 3000;
const SECRET_KEY = "super-secret-key-for-university-project";

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
    res.json({ message: "로그인 성공! 일반 버스 티켓이 발급되었습니다." });
});

// [2] 검증: 통학 버스 탑승 로직 (취약점 존재)
app.get('/board', (req, res) => {
    const token = req.cookies.auth_token;

    if (!token) return res.status(401).send("티켓이 없습니다.");

    try {
        // 취약점 포인트: 헤더를 먼저 확인하기 위해 decode 사용
        const decoded = jwt.decode(token, { complete: true });
        
        if (!decoded || !decoded.header) {
            return res.status(400).send("잘못된 토큰 형식입니다.");
        }

        // 만약 alg가 'none'이면 서명 검증을 하지 않고 페이로드를 신뢰함
        if (decoded.header.alg === 'none') {
            const payload = decoded.payload;
            if (payload.role === 'admin' && payload.bus_type === 'express_home') {
                return res.json({ 
                    success: true, 
                    msg: "프리미엄 급행 버스 탑승 완료! 집으로 빠르게 귀가합니다.",
                    flag: "FLAG{N0NE_ALGORITHM_IS_NOT_SECURE_2026}" 
                });
            } else {
                return res.json({ success: false, msg: "일반 학생은 급행 버스에 탈 수 없습니다." });
            }
        } 

        // 정상적인 HS256 검증 로직
        jwt.verify(token, SECRET_KEY, (err, verified) => {
            if (err) return res.status(403).send("위조된 티켓입니다!");
            res.json({ success: false, msg: "일반 버스에 탑승했습니다. (급행을 타려면 권한이 필요합니다.)" });
        });

    } catch (e) {
        res.status(500).send("서버 에러");
    }
});

app.listen(PORT, () => {
    console.log(`워게임 서버 가동 중: http://localhost:${PORT}`);
});