
import argparse, pytuya

def main():

#command line options parsing
	parse = argparse.ArgumentParser(description="TUYA  RGB Bulb colour changer")

	parse.add_argument("-m", "--mode", help="Specifiy mode of bulb", required=True)
	parse.add_argument("-c", "--scene", help="OPTIONAL - specify red protion of colour defauls 0", required=False, default = 'scene_1')
	parse.add_argument("-x", "--hexcode", help="OPTIONAL - specify hex code of colour defauls 255", required=False, default='9400D30000FF00FF00FFFF00FF7F00FF0000')
	parse.add_argument("-r", "--red", help="OPTIONAL - specify red protion of colour defauls 255", required=False, default='255')
	parse.add_argument("-g", "--green", help="OPTIONAL - specify red protion of colour defauls 0", required=False, default='0')
	parse.add_argument("-b", "--blue", help="OPTIONAL - specify red protion of colour defauls 0", required=False, default='0')
	parse.add_argument("-i", "--brightness", help="OPTIONAL - specify brightness protion defauls 255", required=False, default='255')
	parse.add_argument("-t", "--temperature", help="OPTIONAL - specify temperature protion defauls 255", required=False, default='255')
	parse.add_argument("-s", "--speed", help="OPTIONAL - specify speed portion defauls 50", required=False, default='50')
	
	
	#parse.add_argument("-t", "--typeofnight", help="OPTIONAL - type of night eg Chatting and Drinking etc", required=False, default='')
	
	args = parse.parse_args()

#create some variables
	mode = ""
	#change = True
	scene = 'scene_1'
	
	hexcode = ""
	red = 0
	green = 0
	blue = 0
	brightness = 0
	temperature = 0
	speed = 0
	

#more cli parsing

#change = args.change
	mode = str(args.mode)
	
	scene = str(args.scene)

	hexcode = str(args.hexcode)		
	red = int(args.red)
	green = int(args.green)
	blue = int(args.blue)
	
	temperature = int(args.temperature)
	brightness = int(args.brightness)
	speed = int(args.speed)

	d = pytuya.BulbDevice('DEVICE_ID_HERE', 'IP_ADDRESS_HERE', 'LOCAL_KEY_HERE')
	data = d.status()  # NOTE this does NOT require a valid key
	#print('Dictionary %r' % data)

	if data:
		if mode=="colour":
			print("accepts: red green blue temperature brightness")
			data = d.set_colour(red,green,blue,temperature,brightness)
			# SHOULD DO PART ONE ^^^^ BUT NEED TO CALCULATE HOW
		#>>>>>>>>>>>>>>>>>>>>>>>>>>>>to test <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
			
		elif mode=="on":
			data = d.set_status(True)  # This requires a valid key

		elif mode=="off":
			data = d.set_status(False)  # This requires a valid key

		elif mode=="toggle":
			# Toggle switch state
			switch_state = data['dps']['1']
			data = d.set_status(not switch_state)  # This requires a valid key
			
		elif mode=="white":
			print("accepts: brightness and temperature")
			data = d.set_white(brightness,temperature)  # This requires a valid key
		
		elif mode=="staticscene":
			print("accepts: red green blue temperature brightness")
			data = d.set_static_scene(red,green,blue,temperature,brightness)
		#>>>>>>>>>>>>>>>>>>>>>>>>>>>>to test <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<

			
		elif mode=="onescene":
		#>>>>>>>>>>>>>>>>>>>>>>>>>>>>to test <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
			"""
			Set either scene 1 or scene 3 in one colour for the bulb:
				scene1: fades on/off
				scene3: toggle on/off
			"""
			print("accepts: scene red green blue brightness temperature speed")
			data = d.set_pulse_scene(scene, red, green, blue, brightness, temperature, speed)
				
		elif mode=="multiscene":
		#>>>>>>>>>>>>>>>>>>>>>>>>>>>>to test <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
			"""
			Set either scene 2 or scene 4 in one colour for the bulb:
				scene2: toggle between colours
				scene4: fades between colours
			"""
			print("accepts: scene brightness temperature speed hexcode")
			if scene == 'scene_1':
				scene = 'scene_4'
			data = d.set_multi_scene_ON(scene)
			data = d.set_multi_scene(scene, brightness, temperature, speed, hexcode)
		else:
			print("print help")
		
		data = d.status()  # NOTE this does NOT require a valid key
		print('Dictionary %r' % data)

		#print('state (bool, true is ON) %r' % data['dps']['1'])  # Show status of first controlled switch on device

if __name__ == '__main__':
	main()
