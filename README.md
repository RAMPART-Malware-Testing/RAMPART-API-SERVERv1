# RAMPART-SERVER

# Docker setup
```
docker network create rampart
docker-compose up -d
```

sudo pkill -9 -f 'celery'


# Test Commit

# start process
python start_server.py
python start_celery.py


# Docker run rampart AI
```
docker pull phanuwatkhamtha/malware-api:1.1
docker run -itd --name rampart-ai -p 8081:8000 phanuwatkhamtha/malware-api:1.1
```
