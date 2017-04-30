FROM python:2.7         
ADD . /safenetworking
WORKDIR /safenetworking
EXPOSE 8808
#RUN apt-get install unixodbc unixodbc-dev
RUN apt-get update && apt-get install -y locales unixodbc libgss3 odbcinst devscripts debhelper dh-exec dh-autoreconf libreadline-dev libltdl-dev unixodbc-dev wget unzip
#RUN pip install python-dev
RUN pip install -r requirements.txt
ENTRYPOINT ["python", "untitle5.py"]
MAINTAINER Michael Clark "miclark@paloaltonetworks.com"
