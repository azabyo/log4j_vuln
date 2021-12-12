# log4j 취약점 정리

* log4j는 대부분의 java application에서 범용적으로 사용되는 로깅 라이브러리
* log4j에서 JNDI를 통하여 LDAP이나 DNS lookup 가능하며 제한이 없음
  * java class의 URI도 LDAP이나 DNS lookup의 리턴값으로 가져올 수 있음 
* 환경
  * Victim : log4j 취약점을 갖은 서버
    * e.g.) log.info("X-Api-Version: {}, X-Api-Version);
  * Attacker LDAP 조회 응답 서버
  * Attacker Exploit 코드를 가진 서버
