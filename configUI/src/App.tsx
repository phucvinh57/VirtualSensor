import { Typography } from '@mui/material';
import { green, red } from '@mui/material/colors';
import { useEffect, useState } from 'react';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import useWebSocket, { ReadyState } from 'react-use-websocket';
import './App.css';
import { ConfigDetail } from './configView';
import { HomePage } from './homePage';
import { useAppDispatch } from './redux/hook';
import { addSensor } from './redux/sensorSlice';
import { VirtualSensor } from './types/virtualSensor.d';
import { parseSensorFromStr } from './common';
import { ToastContainer } from 'react-toastify';

function App() {
  const [socketUrl, setSocketUrl] = useState('ws://localhost:9090');
  const dispatch = useAppDispatch()
  
  const { sendMessage, lastMessage, readyState } = useWebSocket(socketUrl, {
    onOpen: () => console.log('Websocket opened'),
    shouldReconnect: (closeEvent) => {
      console.log(`Websocket closed: ${closeEvent}`)
      return true;
    }
  });

  const isConnected = () => {
    return readyState == ReadyState.OPEN;
  }

  useEffect(() => {
    if (lastMessage !== null) {
      const newSensor : VirtualSensor = parseSensorFromStr(lastMessage.data);
      dispatch(addSensor(newSensor));
  }
  }, [lastMessage]);



  return (
    <div className="App">
      <ToastContainer/>
      <Typography display='inline' variant="body1" sx={{paddingBottom: 2}}>
          Config server status:  
          <Typography variant="body1" component='span' color={isConnected() ? green[500] : red[500]}>
          {isConnected() ? ' Connecting' : ' Disconnected'}
          </Typography>
      </Typography>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<HomePage />}/>
          <Route path="/view-config" element={<ConfigDetail />}/>
        </Routes>
      </BrowserRouter>
    </div>
  );
}

export default App;
