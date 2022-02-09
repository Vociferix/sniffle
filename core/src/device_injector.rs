use super::{Device, Packet, Transmit, TransmitError, PDU};

pub struct DeviceInjector {
    dev: std::rc::Rc<Device>,
    injector: pcaprs::Injector,
    buf: Vec<u8>,
}

impl DeviceInjector {
    pub fn new(dev: Device) -> Result<Self, TransmitError> {
        let injector = pcaprs::Injector::new(dev.name())?;
        Ok(Self {
            dev: std::rc::Rc::new(dev),
            injector,
            buf: Vec::new(),
        })
    }

    pub fn device(&self) -> &Device {
        &*self.dev
    }

    pub fn device_mut(&mut self) -> Option<&mut Device> {
        std::rc::Rc::get_mut(&mut self.dev)
    }

    pub fn share_device(&self) -> std::rc::Rc<Device> {
        self.dev.clone()
    }

    pub fn inject_raw(&mut self, data: &[u8]) -> Result<(), TransmitError> {
        self.injector.inject(data)?;
        Ok(())
    }

    pub fn inject_pdu<P: PDU>(&mut self, pdu: &P) -> Result<(), TransmitError> {
        let mut data = std::mem::replace(&mut self.buf, Vec::new());
        data.clear();
        pdu.serialize(&mut data)?;
        self.inject_raw(&data[..])?;
        self.buf = data;
        Ok(())
    }

    pub fn inject(&mut self, packet: &Packet) -> Result<(), TransmitError> {
        self.inject_pdu(packet.pdu())
    }
}

impl Transmit for DeviceInjector {
    fn transmit(&mut self, packet: &Packet) -> Result<(), TransmitError> {
        self.inject(packet)
    }
}
