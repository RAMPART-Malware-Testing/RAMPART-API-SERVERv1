# RAMPART-SERVER

# 1 Docker setup
```
docker network create rampart
docker-compose up -d
```

# 2 MobSF Setup
```
docker run -itd \
  --name mobsf \
  --restart always \
  --network rampart \
  -p 8001:8000 \
  opensecurity/mobile-security-framework-mobsf:latest
```

# start process
```
python start_server.py
python start_celery.py
```

# stop frose 
```
sudo pkill -9 -f 'celery
```

# Docker run rampart AI
```
docker pull phanuwatkhamtha/malware-api:1.1
docker run -itd \
    --name rampart-ai \ 
    --restart always \
    --network rampart \
    -p 8081:8000 \
    phanuwatkhamtha/malware-api:1.1
```
