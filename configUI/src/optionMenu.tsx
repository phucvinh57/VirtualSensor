import * as React from 'react';
import Button from '@mui/material/Button';
import Menu from '@mui/material/Menu';
import MenuItem from '@mui/material/MenuItem';
import MoreVertIcon from '@mui/icons-material/MoreVert';
import { grey } from '@mui/material/colors';
import { VirtualSensor } from './types/virtualSensor.d';
import { Link, useNavigate } from 'react-router-dom';

type MenuProps = {
  sensor: VirtualSensor
}

export const OptionMenu: React.FunctionComponent<MenuProps> = ({sensor}) => {
  const [anchorEl, setAnchorEl] = React.useState<null | HTMLElement>(null);
  const navigate = useNavigate();
  const open = Boolean(anchorEl);
  const handleClick = (event: React.MouseEvent<HTMLButtonElement>) => {
    setAnchorEl(event.currentTarget);
  };
  const handleViewConfig = () => {
    navigate('/view-config', { state: {sensor: sensor} });
    setAnchorEl(null);
  };

  const handleOnClose = () => {
    setAnchorEl(null);
  }

  return (
    <div>
      <Button
        id="basic-button"
        aria-controls={open ? 'basic-menu' : undefined}
        aria-haspopup="true"
        aria-expanded={open ? 'true' : undefined}
        onClick={handleClick}
      >
        <MoreVertIcon sx={{ color: grey[900] }} />
      </Button>
      <Menu
        id="basic-menu"
        anchorEl={anchorEl}
        open={open}
        onClose={handleOnClose}
        MenuListProps={{
          'aria-labelledby': 'basic-button',
        }}
      >
        <MenuItem onClick={handleViewConfig}>
          View Config
        </MenuItem>
        {!sensor.active ? <MenuItem>Untrack</MenuItem> : null}
      </Menu>
    </div>
  );
}