import { FormGroup, TextField, FormControlLabel, Checkbox, Button, Container, Grid, Tooltip, Box, LinearProgress, Alert } from "@mui/material";
import { useEffect, useRef, useState } from "react";
import { useLocation } from "react-router-dom";
import { useAppDispatch, useAppSelector } from "./redux/hook";
import {NumericFormat } from "react-number-format";
import { equalSensors, VirtualSensor, ProcessConfig, SensorConfig } from "./types/virtualSensor.d";
import { SENSOR_CONFIG_ALIAS, SENSOR_CONFIG_HINT } from "./dictionary";
import { toast } from "react-toastify";

enum State {
  VIEWING,
  EDITING,
  SENDING
};

export const ConfigDetail: React.FunctionComponent = () => {
  const storedSensors = useAppSelector(state => state.sensors);
  const {state: locationState} = useLocation();
  const [configSensor, setConfigSensor] = useState<VirtualSensor>(locationState.sensor);
  const [editingSensor, setEditingSensor] = useState<VirtualSensor>(locationState.sensor);

  const [state, setState] = useState<State>(State.VIEWING);

  useEffect(() => {
    const latestSensor : VirtualSensor | undefined = storedSensors.find(s => equalSensors(s, configSensor) && (new Date(s!.lastUpdate as string) > new Date(configSensor!.lastUpdate as string)));
    if (latestSensor) {
      setConfigSensor(latestSensor);
    }
  }, [storedSensors]);

  useEffect(() => {
    if (!state) {
      setEditingSensor(configSensor);
    }
  }, [configSensor])

  const commomSpacing = {
    mr: 2,
    mb: 2
  }

  const renderProcessConfig = () => {
    const processConfig = editingSensor!.config!.filter!.process;
    return <Grid container spacing={2}>
      {(Object.keys(processConfig) as Array<keyof ProcessConfig>)
      .filter(k => typeof processConfig[k] === 'boolean')
      .map(k => {
        const handleChange = (event: React.ChangeEvent<HTMLInputElement>) => {
          let newSensorConfig: VirtualSensor = JSON.parse(JSON.stringify(editingSensor));
          (newSensorConfig!.config!.filter.process[k] as boolean) = event.target.checked;
          state && setEditingSensor(newSensorConfig);
        };
        return <Grid key={k} item xs={2}>
            <FormControlLabel
            key={k}
            checked={processConfig[k] as boolean} 
            control={<Checkbox onChange={handleChange} />} label={k} 
            />
          </Grid>
      })}
    </Grid>;
  }

  const renderOveralConfig = () => {
    return (Object.keys(editingSensor.config as any) as Array<keyof SensorConfig>)
    .filter(k => editingSensor.config && typeof editingSensor.config[k] !== 'object')
    .map(k => {
      const config = editingSensor!.config;
      const value = config ? config[k] : undefined;
      const label = SENSOR_CONFIG_ALIAS[k] ? SENSOR_CONFIG_ALIAS[k] : k;
      if (typeof value === 'number') {
        return <Tooltip key={k} title={SENSOR_CONFIG_HINT[k]} arrow>
            <Box sx={{ display: 'inline-flex' }}>
              <NumericFormat
                value={value} 
                thousandSeparator=','
                customInput={TextField}
                id={k}
                label={label}
                sx = {commomSpacing}
                InputProps={{
                  readOnly: !state,
                }}
              />
            </Box>
          </Tooltip>
      } else if (typeof value == 'string') {
        return <Tooltip key={k} title={SENSOR_CONFIG_HINT[k]} arrow>
          <Box sx={{ display: 'inline-flex' }}>
            <TextField
              id={k}
              label={label}
              sx = {commomSpacing}
              defaultValue={value}
              InputProps={{
                readOnly: !state,
              }}
            />
          </Box>
        </Tooltip>
      }
    });
  }

  const handleClick = () => {
    setState(State.EDITING);
  }

  const handleCancel = () => {
    setState(State.VIEWING);
    setEditingSensor(configSensor);
  }

  const handleSave = () => {
    setState(State.SENDING);
    const id = toast.loading('In progress');
    setTimeout(() => {
      setState(State.VIEWING);
      toast.update(id, 
        {
          render: "Change config successfully",
          closeButton: true, type: "success",
          isLoading: false, 
          autoClose: 1000
        });
    }, 1000);
  }

  const isEditMakeChange = () => {
    return JSON.stringify(configSensor.config) === JSON.stringify(editingSensor.config);
  }
  

  return (
    <Container>
      {state === State.VIEWING 
        ?
        <Button onClick={handleClick} variant="outlined" sx ={commomSpacing}>Edit</Button> 
        :
        <>
          <Button onClick={handleSave} disabled={isEditMakeChange()} color='success' variant="outlined" sx ={commomSpacing}>Save</Button>
          <Button onClick={handleCancel} variant="outlined" sx ={commomSpacing}>Cancel</Button>
        </>
      }
      <div>
        {renderOveralConfig()}
        

        <FormGroup sx={commomSpacing}>
          <FormControlLabel checked={editingSensor.config?.old_kernal} control={<Checkbox />} label="old_kernel" />
          <FormControlLabel checked={editingSensor.config?.dev_flag} control={<Checkbox />} label="dev_flag" />
        </FormGroup> 
      </div>
      <div>
        {renderProcessConfig()}
      </div>
    </Container>
  );
}