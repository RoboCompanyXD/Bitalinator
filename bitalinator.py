#!/usr/bin/env python3

from colors import colors

import re
import time
import argparse
import threading
import signal
import bluetooth
import sys
import os
import multiprocessing
import queue
import json
import pickle
import socket
import uuid
import hashlib
import base64
from textwrap import wrap

from bitalino import BITalino

threadlog = colors.fg.violet+threading.currentThread().getName()+" LOG:"+colors.end
threadsuccess = colors.fg.green+threading.currentThread().getName()+" SUCCESS:"+colors.end
threaderror = colors.fg.red2+threading.currentThread().getName()+" ERROR:"+colors.end
threadcritical = colors.fg.red+threading.currentThread().getName()+" CRITICAL ERROR:"+colors.end
threadcomm = colors.fg.grey+threading.currentThread().getName()+" COMUNICACION:"+colors.end
threadend = colors.fg.blue2+threading.currentThread().getName()+" EXIT:"+colors.end
threadwarning = colors.fg.yellow2+threading.currentThread().getName()+" WARNING:"+colors.end

log = False;

# Funciones auxiliares

def mean(lst): 

	return sum(lst) / len(lst) 

def toInt(a):

	return int(float(a))

# Lista de threads

th_adq = None		#Thread de comunicacion con bitalino y procesador de datos
th_server = None	#Thread servidor de datos para aplicacion android

# Handler de la señal Ctrl + C

def ctrlc_exit(sig, frame):

	if log==True:
		print(threadwarning,'Cerrando...')
	
	if th_adq:

		th_adq.adquiere=0

	if th_server:

		th_server.server=0


	if log==True:
		print(threadend,'Cierre completado')
	os._exit(1)

# Handler de la señal Ctrl + Z

def ctrlz_exit(sig, frame):

	signal.signal(signal.SIGINT, ctrlc_exit)

	if log==True:
		print(threadwarning,'Esperando adq...')
	
	if th_adq:

		th_adq.adquiere=0
		th_adq.join()

	if log==True:
		print(threadwarning,'Esperando server...')

	if th_server:

		th_server.server=0
		th_server.join()
	
	if log==True:
		print(threadend,'Cierre completado')
	os._exit(1)

# Clase sensores para identificarlos

class sensors:

	EMG = 0
	EDA = 1
	ECG = 2
	ACC = 3
	LUX = 4
	
	class names:

		EMG = "EMG"
		EDA = "EDA"
		LUX = "LUX"
		ECG = "ECG"
		ACC = "ACC"

	name = []
	name.insert(EMG,"EMG")
	name.insert(EDA,"EDA")
	name.insert(LUX,"LUX")
	name.insert(ECG,"ECG")
	name.insert(ACC,"ACC")

	stype = {}
	stype["EMG"] = EMG
	stype["EDA"] = EDA
	stype["LUX"] = LUX
	stype["ECG"] = ECG
	stype["ACC"] = ACC

	types = []
	types.append(EMG)
	types.append(EDA)
	types.append(LUX)
	types.append(ECG)
	types.append(ACC)

# Funcion inicializacion de bitalino
# Se añaden funciones para encender y apagar el led

def bitalinoinit(macAddress):

	dev = BITalino(macAddress,15)

	def led_on(dev):
		dev.trigger([0,0,1,0])

	def led_off(dev):
		dev.trigger([0,0,0,0])

	dev.led_on = led_on
	dev.led_off = led_off

	return dev

# Threads

# Thread ADQ: Recive los datos de bitalino, los procesa y los empaqueta

samplingRate = 100
nSamples = 50

#samplingRate = 1000
#nSamples = 500

#samplingRate = 1
#nSamples = 1

nSensors = 5

bitalino = None
bitalinoVersion = None

acqChannels = []

RAW_EMG = []
RAW_EDA = []
RAW_ECG = []
RAW_ACC = []
RAW_LUX = []

def adq(q,bitalino):

	threadlog = '\t'+colors.fg.violet+threading.currentThread().getName()+" LOG:"+colors.end
	threadsuccess = '\t'+colors.fg.green+threading.currentThread().getName()+" SUCCESS:"+colors.end
	threaderror = '\t'+colors.fg.red2+threading.currentThread().getName()+" ERROR:"+colors.end
	threadcritical = '\t'+colors.fg.red+threading.currentThread().getName()+" CRITICAL ERROR:"+colors.end
	threadcomm = '\t'+colors.fg.grey+threading.currentThread().getName()+" COMUNICACION:"+colors.end
	threadend = '\t'+colors.fg.blue2+threading.currentThread().getName()+" EXIT:"+colors.end
	threadwarning = '\t'+colors.fg.yellow2+threading.currentThread().getName()+" WARNING:"+colors.end
	
	buffertime = 10

	EMG_buffer = [0 for i in range(buffertime * samplingRate)]
	EDA_buffer = [0 for i in range(buffertime * samplingRate)]
	ECG_buffer = [0 for i in range(buffertime * samplingRate)]
	ACC_buffer = [0 for i in range(buffertime * samplingRate)]
	LUX_buffer = [0 for i in range(buffertime * samplingRate)]

	acqChannels = [sensors.EMG, sensors.EDA, sensors.ECG, sensors.ACC, sensors.LUX]

	bitalino.start(samplingRate, acqChannels)

	if log==True:
		print(threadsuccess,"ADQ Iniciado")

	it = 0

	samplenumber = 0

	while getattr(threading.currentThread(), "adquiere", 1):

		# Comprobar estado del bitalino

		bitalino.led_on(bitalino)

		try:
			samples = bitalino.read(nSamples)
		except Exception as e:
			if log==True:
				print(threadcritical,e)

			try:
				bitalino = bitalinoinit(macAddress)

			except Exception as e:
		
					if log==True:
						print(threadcritical,"Error bluetooth conectando con el dispositivo,",e)

			else:

				bitalino.start(samplingRate, acqChannels)
				continue

		# Obtener captura almacenar y guardad

		cap_time = int(round(time.time() * 1000))

		RAW_EMG = samples[:,5+sensors.EMG].tolist()
		RAW_EDA = samples[:,5+sensors.EDA].tolist()
		RAW_ECG = samples[:,5+sensors.ECG].tolist()
		RAW_ACC = samples[:,5+sensors.ACC].tolist()
		RAW_LUX = samples[:,5+sensors.LUX].tolist()

		bitalino.led_off(bitalino)

		EMG_buffer[nSamples : len(EMG_buffer)] = EMG_buffer[0 : len(EMG_buffer) - nSamples]
		EDA_buffer[nSamples : len(EDA_buffer)] = EDA_buffer[0 : len(EDA_buffer) - nSamples]
		ECG_buffer[nSamples : len(ECG_buffer)] = ECG_buffer[0 : len(ECG_buffer) - nSamples]
		ACC_buffer[nSamples : len(ACC_buffer)] = ACC_buffer[0 : len(ACC_buffer) - nSamples]
		LUX_buffer[nSamples : len(LUX_buffer)] = LUX_buffer[0 : len(LUX_buffer) - nSamples]

		EMG_buffer[0 : nSamples] = RAW_EMG
		EDA_buffer[0 : nSamples] = RAW_EDA
		ECG_buffer[0 : nSamples] = RAW_ECG
		ACC_buffer[0 : nSamples] = RAW_ACC
		LUX_buffer[0 : nSamples] = RAW_LUX

		sensordata = {}
		sensordata['sensors'] = []
		sensordata['captime'] = cap_time
		sensordata['samplenumber'] = samplenumber

		# Parámetros del procesador

		# EMG

		# EDA

		# ECG

		# ACC

		# LUX

		# Funciones para el procesado de la señal

		def proc_emg():

			#print(threadlog,"Procesando EMG...")

			sensordata['sensors'].insert(sensors.EMG,{})
			sensordata['sensors'][sensors.EMG]['variables'] = []
			sensordata['sensors'][sensors.EMG]['data'] = []
			sensordata['sensors'][sensors.EMG]['data'] = RAW_EMG

		def proc_eda():

			#print(threadlog,"Procesando EDA...")

			sensordata['sensors'].insert(sensors.EDA,{})
			sensordata['sensors'][sensors.EDA]['variables'] = []
			sensordata['sensors'][sensors.EDA]['data'] = []
			sensordata['sensors'][sensors.EDA]['data'] = RAW_EDA

		def proc_ecg():

			#print(threadlog,"Procesando ECG...")

			sensordata['sensors'].insert(sensors.ECG,{})
			sensordata['sensors'][sensors.ECG]['variables'] = []
			sensordata['sensors'][sensors.ECG]['data'] = []
			sensordata['sensors'][sensors.ECG]['data'] = RAW_ECG

		def proc_acc():

			#print(threadlog,"Procesando ACC...")

			sensordata['sensors'].insert(sensors.ACC,{})
			sensordata['sensors'][sensors.ACC]['variables'] = []
			sensordata['sensors'][sensors.ACC]['data'] = []
			sensordata['sensors'][sensors.ACC]['data'] = RAW_ACC

		def proc_lux():

			#print(threadlog,"Procesando LUX...")

			sensordata['sensors'].insert(sensors.LUX,{})
			sensordata['sensors'][sensors.LUX]['variables'] = []
			sensordata['sensors'][sensors.LUX]['variables'].append('mean')
			sensordata['sensors'][sensors.LUX]['variables'].append('max')
			sensordata['sensors'][sensors.LUX]['variables'].append('min')
			sensordata['sensors'][sensors.LUX]['data'] = []
			sensordata['sensors'][sensors.LUX]['data'] = RAW_LUX
			sensordata['sensors'][sensors.LUX]['mean'] = mean(RAW_LUX)
			sensordata['sensors'][sensors.LUX]['min'] = 0.0
			sensordata['sensors'][sensors.LUX]['max'] = 63.0

			#print(threadsuccess,"El nivel actual de luz es",sensordata['sensors'][sensors.LUX]['mean'])

		sns = {	sensors.EMG: proc_emg,
					sensors.EDA: proc_eda,
					sensors.ECG: proc_ecg,
					sensors.ACC: proc_acc,
					sensors.LUX: proc_lux
		}

		# Ejecutar funciones de procesamiento

		for i,s in enumerate(sns,0):
			sns[i]()

		it = it + 1

		# Volcar datos en JSON

		app_json = json.dumps(sensordata)

		# Poner en cola para enviar

		q.put(sensordata)

		#print(threadcomm,"Muestra encolada")

		samplenumber = samplenumber + nSamples

	bitalino.led_off()
	bitalino.stop()

# Thread SERVER: Servidor UPD para la aplicacion android
# Se usa un socket no bloqueante para atender el servidor y la llegada de actualizaciones de samples sin quedarse esperando

scan_keys = ["36dde7d288a2166a651d51ec6ded9e70e72cf6b366293d6f513c75393c57d6f33b949879b9d5e7f7c21cd8c02ede75e74fc54ea15bd043b4df008533fc68ae69"]

pass_hash = "46336fc4408dfbb7ed7a635b3361533fbf297a74cab902a140e6379bc68c182c"    # Manolo

def server(q,):

	threadlog = '\t'+colors.fg.violet+threading.currentThread().getName()+" LOG:"+colors.end
	threadsuccess = '\t'+colors.fg.green+threading.currentThread().getName()+" SUCCESS:"+colors.end
	threaderror = '\t'+colors.fg.red2+threading.currentThread().getName()+" ERROR:"+colors.end
	threadcritical = '\t'+colors.fg.red+threading.currentThread().getName()+" CRITICAL ERROR:"+colors.end
	threadcomm = '\t'+colors.fg.grey+threading.currentThread().getName()+" COMUNICACION:"+colors.end
	threadend = '\t'+colors.fg.blue2+threading.currentThread().getName()+" EXIT:"+colors.end
	threadwarning = '\t'+colors.fg.yellow2+threading.currentThread().getName()+" WARNING:"+colors.end

	class Command:

		CHECK_ONLINE, LOGIN, GET_INFO, START_SAMPLES, STOP_SAMPLES, ASK_SAMPLE, ASK_IMAGE = ("1000", "2000", "3000", "4000", "5000", "6000","7000")

	class Response:

		OK, SCAN_KEY_WRONG, ACC_TOK_WRONG, LOG_TOK_WRONG, IMG_ERROR = ("1001", "1002", "1003", "1004", "1005")

	
	commsock = socket.socket(family=socket.AF_INET, type=socket.SOCK_DGRAM)

	server_address = "0.0.0.0"

	server_port = 27901

	server = (server_address, server_port)

	try:

		commsock.bind(server)

	except socket.error as e:

		if log==True:
			print(threaderror,"Error abriendo conexion en el puerto",server_port,e)
		exit()

	if log==True:
		print(threadlog,"Escuchando conexiones en ",server_address,":",server_port)

	commsock.settimeout(0.01)
	storedata = {}
	storedata['login_key'] = ""
	storedata['sendSamples'] = 0
	storedata['sampling_addr'] = ""

	sampletosend = ""

	
	while getattr(threading.currentThread(), "server", 1):

		try:

			data, client_address = commsock.recvfrom(1024)

		except socket.timeout:

			time.sleep(0.05)

			pass

		except:

			if log==True:
				print(threaderror,"La conexion se ha cerrado, reiniciando...")

			storedata = {}
			storedata['login_key'] = ""
			storedata['sendSamples'] = 0
			storedata['sampling_addr'] = ""

		else:

			if log==True:
				print(threadcomm,str(client_address)," >> ",data.decode())

			query = json.loads(data.decode())

			# Preparar respuesta para todos los comandos posibles

			if query['command'] == Command.CHECK_ONLINE:

				if log==True:
					print(threadcomm,str(client_address)," >> Comprobando comunicacion")

				# Comrpobar query['params']['scan_key']

				if query['params']['scan_key'] in scan_keys:

					response = {}

					response['response'] = Response.OK

					response['params'] = {}

				else:

					response = {}

					response['response'] = Response.SCAN_KEY_WRONG

					response['params'] = {}

					# En caso errónero no se responde

					continue

			if query['command'] == Command.LOGIN:

				if log==True:
					print(threadcomm,str(client_address)," >> Haciendo Login")

				# Crear UUID

				uuidstr = str(uuid.uuid4())

				access_token = hashlib.sha256(uuidstr.encode()).hexdigest()

				storedata['accesstoken'] = access_token
				storedata['login_key'] = ""

				if log==True:
					print(threadsuccess, storedata['accesstoken'])

				response = {}

				response['response'] = Response.OK

				response['params'] = {}

				response['params']['access_token'] = access_token
			
			if query['command'] == Command.GET_INFO:

				if log==True:
					print(threadcomm,str(client_address)," >> Obteniendo informacion")

				# Comrpobar query['params']['login_token']

				if storedata['login_key'] == "":

					posible_logins = []

					for i,k in enumerate(scan_keys,0):

						a = storedata['accesstoken'] + pass_hash + k

						if log==True:
							print(threadwarning,storedata['accesstoken'],pass_hash,k)

						posible_logins.append(hashlib.sha256(a.encode()).hexdigest())

				
					if query['params']['login_key'] in posible_logins:

						storedata['login_key'] = query['params']['login_key']

				if query['params']['login_key'] == storedata['login_key']:

					response = {}

					response['response'] = Response.OK

					response['params'] = {}

					response['params']['device'] = {}

					response['params']['device']['macAddress'] = macAddress
					response['params']['device']['version'] = bitalinoVersion

					response['params']['info'] = {}

					response['params']['info']['nsensors'] = nSensors
					response['params']['info']['samplingRate'] = samplingRate
					response['params']['info']['nSamples'] = nSamples
					response['params']['info']['sensorInfo'] = []

					response['params']['info']['sensorInfo'].insert(len(response['params']['info']['sensorInfo']),sensors.EMG)
					response['params']['info']['sensorInfo'].insert(len(response['params']['info']['sensorInfo']),sensors.EDA)
					response['params']['info']['sensorInfo'].insert(len(response['params']['info']['sensorInfo']),sensors.ECG)
					response['params']['info']['sensorInfo'].insert(len(response['params']['info']['sensorInfo']),sensors.ACC)
					response['params']['info']['sensorInfo'].insert(len(response['params']['info']['sensorInfo']),sensors.LUX)

				else:

					response = {}

					response['response'] = Response.ACC_TOK_WRONG

					response['params'] = {}

					response['params']['info'] = {}

			if query['command'] == Command.START_SAMPLES:

				if log==True:
					print(threadcomm,str(client_address)," >> Activando sampleo")

				if storedata['login_key'] == "" and 'accesstoken' in storedata:

					posible_logins = []

					for i,k in enumerate(scan_keys,0):

						a = storedata['accesstoken'] + pass_hash + k

						if log==True:
							print(threadwarning,storedata['accesstoken'],pass_hash,k)

						posible_logins.append(hashlib.sha256(a.encode()).hexdigest())

				
					if query['params']['login_key'] in posible_logins:

						storedata['login_key'] = query['params']['login_key']

				if query['params']['login_key'] == storedata['login_key']:

					storedata['sendSamples'] = 1

					storedata['sampling_addr'] = ((client_address[0],query['params']['sample_port']))

					response = {}

					response['response'] = Response.OK

					response['params'] = {}

				else:

					response = {}

					response['response'] = Response.ACC_TOK_WRONG

					response['params'] = {}

					response['params']['info'] = {}

			if query['command'] == Command.STOP_SAMPLES:

				if log==True:
					print(threadcomm,str(client_address)," >> Desactivando sampleo")

				if storedata['login_key'] == "" and 'accesstoken' in storedata:

					posible_logins = []

					for i,k in enumerate(scan_keys,0):

						a = storedata['accesstoken'] + pass_hash + k

						if log==True:
							print(threadwarning,storedata['accesstoken'],pass_hash,k)

						posible_logins.append(hashlib.sha256(a.encode()).hexdigest())

				
					if query['params']['login_key'] in posible_logins:

						storedata['login_key'] = query['params']['login_key']

				if query['params']['login_key'] == storedata['login_key']:

					storedata['sendSamples'] = 0

					response = {}

					response['response'] = Response.OK

					response['params'] = {}

				else:

					response = {}

					response['response'] = Response.ACC_TOK_WRONG

					response['params'] = {}

					response['params']['info'] = {}

			if query['command'] == Command.ASK_SAMPLE:

				if log==True:
					print(threadcomm,str(client_address)," >> Solicitando muestra")

				if storedata['login_key'] == "" and 'accesstoken' in storedata:

					posible_logins = []

					for i,k in enumerate(scan_keys,0):

						a = storedata['accesstoken'] + pass_hash + k

						if log==True:
							print(threadwarning,storedata['accesstoken'],pass_hash,k)

						posible_logins.append(hashlib.sha256(a.encode()).hexdigest())

				
					if query['params']['login_key'] in posible_logins:

						storedata['login_key'] = query['params']['login_key']

				if query['params']['login_key'] == storedata['login_key']:

					response = {}

					response['response'] = Response.OK

					response['params'] = {}

					response['params']['sample'] = sampletosend

				else:

					response = {}

					response['response'] = Response.ACC_TOK_WRONG

					response['params'] = {}

					response['params']['info'] = {}

			if query['command'] == Command.ASK_IMAGE:

				if log==True:
					print(threadcomm,str(client_address)," >> Solicitando imagen")

				if storedata['login_key'] == "" and 'accesstoken' in storedata:

					posible_logins = []

					for i,k in enumerate(scan_keys,0):

						a = storedata['accesstoken'] + pass_hash + k

						if log==True:
							print(threadwarning,storedata['accesstoken'],pass_hash,k)

						posible_logins.append(hashlib.sha256(a.encode()).hexdigest())

				
					if query['params']['login_key'] in posible_logins:

						storedata['login_key'] = query['params']['login_key']

				if query['params']['login_key'] == storedata['login_key']:


					try:

						with open("/tmp/robonitor/cap.jpg", "rb") as image_file:

							encoded_image = base64.b64encode(image_file.read()).decode("utf-8")
							encoded_imagesize = len(encoded_image)

					except:

						if log==True:
							print(threaderror,"Error al abrir la captura")

						response = {}

						response['response'] = Response.IMG_ERROR

						response['params'] = {}

					else:

						# Preparar imagen

						#hacer chunks de 4Kb

						#chunksize = 4096
						chunksize = 40960

						image_chunks = wrap(encoded_image,chunksize)
						nimage_chunks = len(image_chunks)

						if log==True:
							print(threadcomm,"Enviando imagen >> ", str(client_address))

						response = {}

						response['response'] = Response.OK

						response['params'] = {}

						response['params']['imagesize'] = encoded_imagesize
						response['params']['nchunks'] = nimage_chunks
						response['params']['chunksize'] = chunksize
						

				else:

					response = {}

					response['response'] = Response.ACC_TOK_WRONG

					response['params'] = {}

					response['params']['info'] = {}

			# Enviar respuesta

			if query['command'] in [Command.CHECK_ONLINE, Command.LOGIN, Command.GET_INFO, Command.START_SAMPLES, Command.STOP_SAMPLES, Command.ASK_SAMPLE, Command.ASK_IMAGE]:

				response_string = json.dumps(response)

				if log==True:
					print(threadcomm,"Enviando respuesta ", response_string,">>",str(client_address))

				commsock.sendto(response_string.encode(), client_address)
				#response['params']['access_token'] = access_token

				#print(threadcomm,str(client_address)," >> ",data.decode())
				#sent = commsock.sendto(data, client_address)

			#Transfer image

			if query['command'] in [Command.ASK_IMAGE]:

				for i,t in enumerate(image_chunks,0):

					chunktosend = {}
					chunktosend['nchunk'] = i

					chunktosend ['data'] = t

					chunktosend_string = json.dumps(chunktosend)

					if log==True:
						print(threadcomm,"Enviando chunk de imagen ", chunktosend_string,">>",str(client_address))

					commsock.sendto(chunktosend_string.encode(), client_address)

					commsock.settimeout(1)

					try:

						data, client_address = commsock.recvfrom(2)

					except socket.timeout:

						time.sleep(0.05)

						break

					print(threadcomm,data.decode())

			commsock.settimeout(0.01)

		sample = None

		# Reemplazo if not q.empty() para poder usar queue no bloqueante:

		try:

			sample = q.get(True,0)

		except(queue.Empty):

			time.sleep(0.05)

			pass

		if sample is not None:

			if storedata['sendSamples'] == 1:

				sampletosend = sample
				sample_string = json.dumps(sampletosend)

				#print(threadcomm,"Enviando muestra >> ",str(storedata['sampling_addr']))
				#commsock.sendto(sample_string.encode(), storedata['sampling_addr'])

				#print(threadcomm,"Enviando muestra >> ",str(client_address))
				#commsock.sendto(sample_string.encode(), client_address)

sample_queue = queue.Queue()


if __name__ == "__main__":

	threadlog = colors.fg.violet+threading.currentThread().getName()+" LOG:"+colors.end
	threadsuccess = colors.fg.green+threading.currentThread().getName()+" SUCCESS:"+colors.end
	threaderror = colors.fg.red2+threading.currentThread().getName()+" ERROR:"+colors.end
	threadcritical = colors.fg.red+threading.currentThread().getName()+" CRITICAL ERROR:"+colors.end
	threadcomm = colors.fg.grey+threading.currentThread().getName()+" COMUNICACION:"+colors.end
	threadend = colors.fg.blue2+threading.currentThread().getName()+" EXIT:"+colors.end
	threadwarning = colors.fg.yellow2+threading.currentThread().getName()+" WARNING:"+colors.end

	# Parsear argumentos

	parser = argparse.ArgumentParser(
			description="Procesador de monitorización de bitalino.",
			epilog="Creado por Christian Martín y Borja Gómez")

	parser._positionals.title = 'Positional arguments'
	parser._optionals.title = 'Argumentos opcionales'
	parser._actions[0].help='Mostrar ayuda del programa'
		
	parser.add_argument("-m","--mac",
		action="store",
		required=False,
		help="Direccion MAC del dispositivo Bitalino.")

	parser.add_argument("-l","--log",
		action='store_true',
		required=False,
		help="Mostrar registro")

	args = parser.parse_args()

	log = args.log

	if args.mac != None:
		if re.match("[0-9a-f]{2}([-:]?)[0-9a-f]{2}(\\1[0-9a-f]{2}){4}$", args.mac.lower()):

			macAddress = args.mac

			if log==True:
				print(threadlog, "Utulizando dirección mac:", macAddress)

		else:

			print(threaderror, "La direccion mac introcucida no tiene formato válido.")
			os._exit(1)
	else:

		#macAddress = "98:D3:31:B2:14:90"
		macAddress = "0C:61:CF:29:8F:22"

		if log==True:
			print(threadlog, "Utulizando dirección mac por defecto:", macAddress)


	if log==True:
		print(threadlog, "Cargando...")

	signal.signal(signal.SIGINT, ctrlc_exit)

	if os.name == 'nt':
		pass
	else:
		signal.signal(signal.SIGTSTP, ctrlz_exit)

	if log==True:
		print(threadlog, "Contactando con bitalino")

	batteryThreshold = 30

	try:
		bitalino = bitalinoinit(macAddress)

	except Exception as e:
		
		if log==True:
			print(threadcritical,"Error bluetooth conectando con el dispositivo,",e)

	else:

		#bitalino.battery(batteryThreshold)

		bitalinoVersion = bitalino.version()

		if log==True:
			print(threadsuccess,"Conexion correcta con",bitalinoVersion)


		if log==True:
			print(threadlog,"Lanzando ADQ...")

		th_adq = threading.Thread(name="ADQ",target=adq, args=(sample_queue,bitalino))
		th_adq.start()


	if log==True:
		print(threadlog,"Lanzando Servidor...")

	th_server = threading.Thread(name="Server",target=server, args=(sample_queue,))
	th_server.start()

	th_server.join()
	th_adq.join()

	
