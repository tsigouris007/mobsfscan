# A rewritten mobsfscan Dockerfile

This image uses: https://pypi.org/project/mobsfscan/ \
This uses version `0.3.4`.

## Why?

Because we add a customized / normalized report fitting to our needs.

## How?

### Build

```bash
docker build . -t mobsfscan:0.3.4 # or whatever you wanna call it
```

### Run

It is preferable to mount the `/data` folder as shown with your current project's folder in order to receive a proper `report.mobsfscan.json` file as an output.

```bash
docker run --rm -v $(pwd):/data mobsfscan:0.3.4 /data
```

This will copy the two report files to your mounted folder.
