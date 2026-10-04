import socket

s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(('0.0.0.0', 1389))
s.listen(1)
s.settimeout(15)

print("Dang cho ket noi tren port 1389 (toi da 15 giay)...")
try:
    conn, addr = s.accept()
    print("KET NOI TU:", addr)
    conn.close()
except socket.timeout:
    print("KHONG CO KET NOI SAU 15 GIAY - bien phap khac phuc co hieu qua")
s.close()