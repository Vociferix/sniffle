use super::*;

#[derive(Debug)]
pub struct AsyncInjector(Option<Injector>);

impl AsyncInjector {
    pub fn new<D: AsDeviceName>(device: D) -> Result<Self> {
        Ok(Self(Some(Injector::new(device)?)))
    }

    pub async fn inject(&mut self, data: &[u8]) -> Result<()> {
        unsafe {
            // This should be OK since the spawned task is immediately joined... I think?
            let data: &'static [u8] = std::mem::transmute(data);
            let injector = self.0.take().unwrap();
            let res = tokio::task::spawn_blocking(
                move || -> std::result::Result<Injector, (Injector, PcapError)> {
                    let mut injector = injector;
                    let res = injector.inject(data);
                    match res {
                        Ok(()) => Ok(injector),
                        Err(e) => Err((injector, e)),
                    }
                },
            )
            .await
            .unwrap();
            match res {
                Ok(injector) => {
                    self.0 = Some(injector);
                    Ok(())
                }
                Err((injector, e)) => {
                    self.0 = Some(injector);
                    Err(e)
                }
            }
        }
    }
}
