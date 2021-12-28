# Xiaomi Mi BLE JAVA client

## Description
In order to make the Mi authentication accessible to Java clients, i.e. Android based systems, I have ported my original work from [miauth](). If you want to understand the authentication process: I have fully described the communication protocol and cryptography in the [Documentation](doc/).

## Installation
Simply import the `miauth` folder into your project.

## Using the library
...

### Initialization
1. Implement IDevice interface
2. Create IDevice instance
3. (Optional) Extend Data class to your needs, e.g. functions for saving/loading token
```
// implement IDevice interface, i.e. using RxAndroidBle
BleClientImpl bleClient = new BleClientImpl(this);
// bleClient.scan() ...

IDevice device = bleClient.getDevice("11:22:33:44:55:55");

// extend Data class, i.e. to include additional functions for saving/loading token
MyData data = new MyData()
```

### Registration
```
dataRegister = new DataRegister(data);
auth = new AuthRegister(device, data, complete -> {
    if (complete) {
        // disconnect complete process and save token
        auth.disconnect();
        data.save();

        textSerialNo.setText("Registration successful");
    } else {
        // disconnect device only and capture button press
        device.disconnect();

        Toast.makeText(this, "Press POWER button within 5 secs after the beep!", Toast.LENGTH_SHORT).show();
        new Handler(Looper.getMainLooper()).postDelayed(() -> auth.start(), 5000);
    }
});
// send command to register
auth.start();
```

### Login / Comm
```
DataLogin dataLogin = new DataLogin(data);
auth = new AuthLogin(device, dataLogin, complete -> {
    if (complete) {
        auth = new AuthComm(device, dataLogin, message -> {
            auth.disconnect();

            String serialNo = new String(message);
            Log.println(Log.INFO, "main", serialNo);
            textSerialNo.setText(serialNo);
        });
        // send command to get serial number 
        auth.start();
    }
});
// send command to login
auth.start();
```

## License
See LICENSE.md

## Disclaimer
I'm in no way affiliated with Xiaomi or any of their subsidiaries and products. This code has been provided for research purposes only.
