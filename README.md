# Tiny Second-hand Shopping Platform

Flask 기반으로 제작된 중고거래 플랫폼입니다.  
시큐어코딩 과제를 위한 실습 프로젝트로 비밀번호 해시, 세션 보호 등의 기능을 포함하고 있습니다.

# 주요 기능
- 사용자 회원가입 / 로그인
- 상품 등록 및 거래
- 포인트 충전 및 송금
- 사용자 간 1:1 채팅 기능
- 신고 및 관리자 차단/삭제 처리 기능
- 후기 작성
- 관리자 권한

# 실행 방법
```bash
git clone https://github.com/seoonju/secure-coding
conda env create -f enviroments.yaml
pip install bcrypt
python app.py

# 사전 설치
- 아나콘다 설치 https://docs.anaconda.com/free/miniconda/index.html
- ngrok 가입
