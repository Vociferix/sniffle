use super::{Device, Error, Packet, Pdu, RawPacket, Transmit};
use async_trait::async_trait;

pub struct DeviceInjector {
    dev: std::sync::Arc<Device>,
    injector: pcaprs::AsyncInjector,
    buf: Vec<u8>,
}

impl DeviceInjector {
    pub fn new(dev: Device) -> Result<Self, Error> {
        let injector = pcaprs::AsyncInjector::new(dev.name())?;
        Ok(Self {
            dev: std::sync::Arc::new(dev),
            injector,
            buf: Vec::new(),
        })
    }

    pub fn device(&self) -> &Device {
        &self.dev
    }

    pub fn device_mut(&mut self) -> Option<&mut Device> {
        std::sync::Arc::get_mut(&mut self.dev)
    }

    pub fn share_device(&self) -> std::sync::Arc<Device> {
        self.dev.clone()
    }

    pub async fn inject_raw(&mut self, data: &[u8]) -> Result<(), Error> {
        self.injector.inject(data).await?;
        Ok(())
    }

    pub async fn inject_pdu<P: Pdu>(&mut self, pdu: &P) -> Result<(), Error> {
        let mut data = std::mem::take(&mut self.buf);
        data.clear();
        pdu.serialize(&mut data)?;
        self.inject_raw(&data[..]).await?;
        self.buf = data;
        Ok(())
    }

    pub async fn inject(&mut self, packet: &Packet) -> Result<(), Error> {
        self.inject_pdu(packet.pdu()).await
    }
}

#[async_trait]
impl Transmit for DeviceInjector {
    async fn transmit_raw(&mut self, packet: RawPacket<'_>) -> Result<(), Error> {
        self.inject_raw(packet.data()).await
    }

    async fn transmit(&mut self, packet: &Packet) -> Result<(), Error> {
        self.inject(packet).await
    }
}
