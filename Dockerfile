FROM python:3.6.6
WORKDIR /usr/src/app
COPY . .
RUN pip3 install -r requirements.txt
RUN bash -c "/usr/src/app/fix.sh"
ENTRYPOINT [ "/usr/src/app/src/domainanalyzer/domainanalyzer.py" ]
