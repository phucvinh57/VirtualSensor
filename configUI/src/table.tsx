import { DataGrid, GridColDef, GridRenderCellParams, GridEventListener } from '@mui/x-data-grid';
import {OptionMenu} from './optionMenu';
import { VirtualSensor } from './types/virtualSensor.d';
import { Avatar } from '@mui/material';
import { green, red } from '@mui/material/colors';

const columns: GridColDef[] = [
  { field: 'active',
    headerName: 'State',
    width: 100,
    renderCell: (params: GridRenderCellParams<boolean>) => {
      const isActive: boolean | undefined = params.value;
      const sx = {
        fontSize: '0.75rem',
        bgcolor: isActive ? green[500] : red[500],
        width: '100%',
        height: '50%'
      }
      return  <Avatar variant="rounded" sx={sx}>
                { isActive ? 'Active' : 'Dead'}
              </Avatar>
    },
    sortable: false
  },
  { field: 'name', headerName: 'Name', flex: 1 },
  { field: 'cluster', headerName: 'Cluster', flex: 1 },
  { 
    field: 'description', 
    headerName: 'Description', 
    flex: 1
  },
  {
    field: 'menu',
    headerName: 'Menu',
    width: 90,
    renderCell: (params: GridRenderCellParams<VirtualSensor>) => {
      return params.value ? <OptionMenu sensor={params.value}></OptionMenu> : <span>empty</span>
    },
    sortable: false
  }
];

const toRows = (sensors: VirtualSensor[]) => {
  return  sensors.map(s => ({
    id: `${s.id}`,
    name: s.info!.name,
    cluster: s.info!.name,
    active: s.active,
    description: s.info!.description,
    menu: s
  }));
}

type TableProps = {
  data: VirtualSensor[]
}

export const DataTable: React.FunctionComponent<TableProps> = ({data}) => {


  return (
    <div style={{ height: 400, width: '100%' }}>
      <DataGrid
        rows={toRows(data)}
        columns={columns}
        pageSize={5}
        rowsPerPageOptions={[5]}
        disableSelectionOnClick
      />
    </div>
  );
}