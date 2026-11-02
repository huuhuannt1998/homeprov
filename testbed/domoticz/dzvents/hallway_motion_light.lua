-- HOMEPROV E-DZ: motion-activated light, hallway configuration (the Domoticz analogue of the motion-light automation).
-- Motion on turns the light on; motion off turns it off. Domoticz records the light's rows with the User
-- "EventSystem/hallway_motion_light", the label the laundering arm borrows.
return {
	on = { devices = { 'SensorHub - Hallway Motion' } },
	execute = function(domoticz, device)
		if device.state == 'On' then
			domoticz.devices('Hallway Light').switchOn()
		else
			domoticz.devices('Hallway Light').switchOff()
		end
	end
}
