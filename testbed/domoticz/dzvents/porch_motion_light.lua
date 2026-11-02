-- HOMEPROV E-DZ: motion-activated light, porch configuration (the Domoticz analogue of the motion-light automation).
-- Motion on turns the light on; motion off turns it off. Domoticz records the light's rows with the User
-- "EventSystem/porch_motion_light", the label the laundering arm borrows.
return {
	on = { devices = { 'SensorHub - Porch Motion' } },
	execute = function(domoticz, device)
		if device.state == 'On' then
			domoticz.devices('Porch Light').switchOn()
		else
			domoticz.devices('Porch Light').switchOff()
		end
	end
}
