import { Typography } from "@mui/material";
import { green, red } from "@mui/material/colors";
import { useEffect, useState } from "react";
import useWebSocket, { ReadyState } from "react-use-websocket";
import { useAppSelector, useAppDispatch } from "./redux/hook";
import { addSensor } from "./redux/sensorSlice";
import { DataTable } from "./table";
import { equalSensors, VirtualSensor } from "./types/virtualSensor.d";

export const HomePage = () => {
    const storedSensors = useAppSelector(state => state.sensors)
    const dispatch = useAppDispatch()

    // Add uiSensors state to avoid refreshing table when state of virtual sensor does not change
    const [uiSensors, setUiSensors] = useState<VirtualSensor[]>([])



    useEffect(() => {
        if (storedSensors.length === uiSensors.length &&
            uiSensors.every(s => storedSensors.find(z => equalSensors(s, z) && s.active === z.active))) {
                return;
            } else {
                setUiSensors(storedSensors);
            }
    }, [storedSensors])
  


    return (
        <div>
            <DataTable data={uiSensors}/>
        </div>
    )
}