# Kknd Root Detector

Kknd Root Detector is a lightweight Android application that checks whether a device may be rooted or running in a potentially insecure environment.

The project demonstrates common techniques used by security‑sensitive Android apps to detect root access and system modifications.

This project is intended mainly for: 
- Android security learning 
- Developers implementing root detection 
- Reverse engineering practice 
- Educational demonstrations
  
Kknd Root Detector is a lightweight Android application that checks
whether a device may be rooted or running in a potentially insecure
environment.

The project demonstrates common techniques used by security‑sensitive
Android apps to detect root access and system modifications.

This project is intended mainly for: 
- Android security learning 
- Developers implementing root detection 
- Reverse engineering practice 
- Educational demonstrations

------------------------------------------------------------------------

## Features


The application performs several checks typically used in root detection systems:

The application performs several checks typically used in root detection
systems:

-   Detection of **`su` binary** in common system paths
-   Detection of **known root management apps**
-   Basic **system integrity checks**
-   Detection of **suspicious files and directories**
-   Native‑based detection methods inspired by security research

These checks help determine whether the device environment might be
compromised.

------------------------------------------------------------------------

## Installation

You can download the latest APK from the **GitHub Releases page**:

https://github.com/juanma0511/Kknd_Root_Detector/releases

Or build it yourself following the instructions below.

------------------------------------------------------------------------

## Build From Source

### Requirements

-   Android Studio
-   Android SDK
-   JDK 17 (recommended)
-   Gradle (included via wrapper)

### Steps

Clone the repository:

``` bash
git clone https://github.com/juanma0511/Kknd_Root_Detector.git
cd Kknd_Root_Detector
```

Open the project with **Android Studio** and build it normally.

Or build from the command line:

``` bash
./gradlew assembleDebug
```

The generated APK will be located at:

    app/build/outputs/apk/debug/*.apk

------------------------------------------------------------------------

## Project Preview

<img src="https://github.com/juanma0511/Kknd_Root_Detector/blob/main/art/rootdetection.jpg" width="350">

------------------------------------------------------------------------

## Use Cases

This project can be useful for:

-   Testing rooted Android devices
-   Studying how apps detect root access
-   Learning Android security concepts
-   Developing root detection features in apps

------------------------------------------------------------------------

## Credits

Native detection ideas inspired by:

https://github.com/reveny/Android-Native-Root-Detector

------------------------------------------------------------------------

## Reporting Issues

If you find a bug:

-   Open an issue:\
    https://github.com/juanma0511/Kknd_Root_Detector/issues

-   Or contact via Telegram:\
    https://t.me/juanma0511

------------------------------------------------------------------------

## Disclaimer

This project is provided for **educational and research purposes only**.

Do not use it to bypass security protections in applications without authorization.


