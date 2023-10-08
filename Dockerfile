# Utiliza una imagen base de Python
FROM python:3.7-slim

# Establece el directorio de trabajo en /app
WORKDIR /app

# Copia el archivo de requerimientos al contenedor
COPY requirements.txt .

# Instala las dependencias de la aplicación
RUN pip install --no-cache-dir -r requirements.txt

# Instala Gunicorn
RUN pip install gunicorn

# Copia el contenido de la aplicación al contenedor
COPY . .

# Establece el usuario como root
USER root

# Expone el puerto en el que la aplicación Flask se ejecutará (generalmente el puerto 5000)
EXPOSE 8080

# Comando para iniciar la aplicación con Gunicorn, leyendo el Procfile
CMD ["sh", "-c", "gunicorn $(cat Procfile)"]