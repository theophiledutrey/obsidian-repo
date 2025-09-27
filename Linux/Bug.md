# Chrome – Profile Already In Use / Locked

**Symptom**  
When launching Chrome:  
```
The profile appears to be in use by another Google Chrome process on another computer (fedora).  
Chrome has locked the profile so that it doesn't get corrupted.
```

**Solution**  
1. Check that no Chrome processes are running:  
```bash
ps aux | grep chrome
killall -9 chrome
```

2. Remove the lock files:  
```bash
rm -f ~/.config/google-chrome/SingletonLock
rm -f ~/.config/google-chrome/SingletonSocket
rm -f ~/.config/google-chrome/SingletonCookie
```

3. Relaunch Chrome:  
```bash
google-chrome &
```
