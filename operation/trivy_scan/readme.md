# trivy를 다운로드 받아서, 보안취약성 검사를 수행하고, 결과 수치를 VCF Operations에 전달합니다.

### 전달 방법
1방안. 각 운영체제에서 script를 실행하고, 출력 결과 합을 VCF Ops에 바로 API 호출로 메트릭을 주입합니다.
2방안. 각 운영체제에서 script를 실행하고, 출력 결과 합을 DB로 전달합니다. DB로 전달된 데이터는 DB 서버에서 VCF Ops로 API 호출로 메트릭을 주입합니다.
  - NGINX, Python server를 사용하여, web server를 호스팅할 수 있습니다.

고객이 보유한 scan script 도구가 있다면, 결과 값에 대한 수치를 VCF Operations로 전달하여, VCF Operations 대시보드를 구성하여, 상시 점검할 수 있도록 구성을 제공할 수 있습니다.

### VCF Operations의 화면
- VCF Operations에서는 Resoure Adapter, Resource-Kind를 메트릭 주입 스크립트를 실행 시 없는 경우에는 API 호출을 통해서 생성하며, 이후 metric으로 주입합니다.
<img width="1518" height="788" alt="image" src="https://github.com/user-attachments/assets/4ee2f276-e736-4a23-adf5-d91dcd7b76b0" />

### Nginx web server 화면
<img width="1522" height="667" alt="image" src="https://github.com/user-attachments/assets/8a3bf01b-c28a-4440-b792-d64db84c3db0" />
