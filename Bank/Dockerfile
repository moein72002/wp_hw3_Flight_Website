FROM python:3.9-buster
WORKDIR /app
RUN pip3 install django djangorestframework
COPY . ./
RUN python manage.py migrate
EXPOSE 8000
CMD [ "python", "manage.py", "runserver", "0.0.0.0:8000" ]  