# blog
=======
# Ezpz 
1. Ae vào data/members.toml để chỉnh thông tin cá nhân , avatar thì lưu ở static/icons/???.png
2. Viết wu thì tui có làm file gen.py ở content/writeups
```sh
    python3 gen.py $CTF_NAME $CHALL_NAME
```
Chạy lệnh sẽ tạo ra 1 file CTF_NAME.md và 1 folder CTF_NAME/CHALL_NAME.md . Sau đó chính sửa thông tin cho phù hợp là được.

3. Nếu thêm hình thì vào  lưu vào static/images hoặc là lưu trên hackmd xong publish ra rr để thẳng link vào luôn :v 

# Build 
Build dưới local : 
```sh
    git submodule init
    git submodule update
    hugo server -D
```
**Khi lên server thì chỉ hiện thị tên giải ở phần WriteUps thui. Flag -D để tên challenge cũng hiện ở WriteUps Local cho dễ debug thui.**
- Ví dụ ae muốn viết 1 technique j đó thui chứ không trong giải ctf nào thì tạo file ở /writeups  với **type = 'list'** tương tự với **CTF_NAME.md** là được 

# blog
