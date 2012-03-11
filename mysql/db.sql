drop table if exists pool;
drop table if exists os;
--
-- Table structure for table 'P0f'
--

CREATE TABLE pool (
  IP varchar(15) NOT NULL default '',
  Hops int(11) NOT NULL default '0',
  OS int(11) NOT NULL default '0',
  sport int(11) default NULL,
  dport int(11) default NULL,
  time timestamp(14) NOT NULL,
  UNIQUE KEY IP (IP,dport,OS)
) TYPE=MyISAM;

--
-- Dumping data for table 'P0f'
--

CREATE TABLE os (
  osid int(11) NOT NULL default '0' auto_increment,
  osname text default NULL,
  win int,
  ttl int,
  mss int,
  df int,
  wscale int,
  sok int,
  nop int,
  size int,
  PRIMARY KEY  (osid)
) TYPE=MyISAM;

