# compile the aar for android 

- download and install the gomobile
- execute command: gomobile bind -v -o android.aar -target=android -androidapi 30 ./vpncore
- check jar file and aar file 

gomobile bind -v -o android.aar -target=android -androidapi 30 -ldflags '-w -s' /home/evan/GoWorks/src/chimney3/vpncore