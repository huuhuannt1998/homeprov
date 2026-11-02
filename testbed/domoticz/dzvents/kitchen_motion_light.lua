-- HOMEPROV E-DZ: motion-activated light, kitchen configuration (the Domoticz analogue of the motion-light automation).
-- Motion on turns the light on; motion off turns it off. Domoticz records the light's rows with the User
-- "EventSystem/kitchen_motion_light", the label the laundering arm borrows.
return {
	on = { devices = { 'SensorHub - Kitchen Motion' } },
	execute = function(domoticz, device)
		if device.state == 'On' then
			domoticz.devices('Kitchen Light').switchOn()
		else
			domoticz.devices('Kitchen Light').switchOff()
		end
	end
}
