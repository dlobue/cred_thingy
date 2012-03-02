# vi: ts=4 expandtab
#
#    Copyright (C) 2009-2010 Canonical Ltd.
#
#    Author: Scott Moser <scott.moser@canonical.com>
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License version 3, as
#    published by the Free Software Foundation.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU General Public License for more details.
#
#    You should have received a copy of the GNU General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import yaml

starts_with_mappings={
    '#include' : 'text/x-include-url',
    '#!' : 'text/x-shellscript',
    '#cloud-config' : 'text/cloud-config',
    '#upstart-job'  : 'text/upstart-job',
    '#part-handler' : 'text/part-handler',
    '#cloud-boothook' : 'text/cloud-boothook',
    '#cloud-config-archive' : 'text/cloud-config-archive',
}


def explode_cc_archive(archive,parts):
    for ent in yaml.load(archive):
        # ent can be one of:
        #  dict { 'filename' : 'value' , 'content' : 'value', 'type' : 'value' }
        #    filename and type not be present
        # or
        #  scalar(payload)
        filename = 'part-%03d' % len(parts['content'])
        def_type = "text/cloud-config"
        if isinstance(ent,str):
            content = ent
            mtype = type_from_startswith(content,def_type)
        else:
            content = ent.get('content', '')
            filename = ent.get('filename', filename)
            mtype = ent.get('type', None)
            if mtype == None:
                mtype = type_from_startswith(content,def_type)

        print "adding %s,%s" % (filename, mtype)
        parts['content'].append(content)
        parts['names'].append(filename)
        parts['types'].append(mtype)
    
def type_from_startswith(payload, default=None):
    # slist is sorted longest first
    slist = sorted(starts_with_mappings.keys(), key=lambda e: 0-len(e))
    for sstr in slist:
        if payload.startswith(sstr):
            return(starts_with_mappings[sstr])
    return default

def process_includes(msg,parts):
    # parts is a dictionary of arrays
    # parts['content']
    # parts['names']
    # parts['types']
    for t in ( 'content', 'names', 'types' ):
        if not parts.has_key(t):
            parts[t]=[ ]
    for part in msg.walk():
        # multipart/* are just containers
        if part.get_content_maintype() == 'multipart':
            continue

        payload = part.get_payload()

        ctype = None
        ctype_orig = part.get_content_type()
        if ctype_orig == "text/plain":
            ctype = type_from_startswith(payload)

        if ctype is None:
            ctype = ctype_orig

        #if ctype == 'text/x-include-url':
            #do_include(payload,parts)
            #continue

        if ctype == "text/cloud-config-archive":
            explode_cc_archive(payload,parts)
            continue

        filename = part.get_filename()
        if not filename:
            filename = 'part-%03d' % len(parts['content'])

        parts['content'].append(payload)
        parts['types'].append(ctype)
        parts['names'].append(filename)



