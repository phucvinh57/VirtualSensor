import { createSlice, PayloadAction } from '@reduxjs/toolkit'
import { VirtualSensor, equalSensors } from '../types/virtualSensor.d'
import type { RootState } from './store'

const initialState: VirtualSensor[] = []

export const sensorSlice = createSlice({
  name: 'sensors',
  // `createSlice` will infer the state type from the `initialState` argument
  initialState,
  reducers: {
    addSensor: (state, action: PayloadAction<VirtualSensor>) => {
      state = [action.payload, ...state.filter(s => !equalSensors(s, action.payload))]
      return state
    }
  }
})

export const { addSensor } = sensorSlice.actions

export default sensorSlice.reducer