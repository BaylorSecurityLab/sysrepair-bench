@echo off
rem BUILD-TIME ONLY. One-shot ManageEngine Desktop Central licence registration.
rem
rem Desktop Central 9.1.0 refuses to start until its licence agreement has been
rem answered and lib\AdventNetLicense.xml exists. The console registration
rem wizard reads every answer through
rem com.adventnet.tools.prevalent.CMDClass.getInput(), which is:
rem
rem     new BufferedReader(new InputStreamReader(System.in)).readLine().trim()
rem
rem constructed fresh for each question and then discarded. Two consequences,
rem both measured on this image:
rem
rem   1. Under the bundled Tanuki wrapper (Wrapper.exe -s as a service OR
rem      DCService.bat -c in console mode) the JVM's System.in is not connected
rem      to anything. readLine() returns null, .trim() throws inside getInput()'s
rem      own catch, getInput() returns null, and userChoice() dies on
rem      null.equalsIgnoreCase("y") -- the NullPointerException at
rem      CMDClass.java:217. That NPE aborts licence acquisition, so LICENSETYPE
rem      stays 0, Wield.isBare() then calls RestoreBackUp with a null
rem      ErrorDetails and NPEs again at RestoreBackUp.java:94, and the JVM
rem      prints "Problem while Starting Server" and exits. It is a hard failure,
rem      not a slow start: waiting cannot fix it.
rem
rem   2. Each BufferedReader buffers up to 8192 characters before handing back
rem      one line, then is thrown away along with the rest of that buffer. A
rem      small answer file is therefore swallowed whole by the first prompt and
rem      every later prompt sees EOF -- which is the same null as case 1.
rem
rem So the wizard is answered exactly once, here, by starting the JVM directly
rem (no wrapper, so System.in is a real handle) with stdin redirected from an
rem answer file deliberately larger than 8192 bytes per prompt. Desktop Central
rem writes lib\AdventNetLicense.xml (a byte-for-byte copy of the shipped
rem lib\Free.xml -- the perpetual Free Edition, no expiry to age out of) and
rem updates lib\petinfo.dat. Both are plain files in the image layer, so the
rem service starts cleanly from then on and no runtime step is needed.
rem
rem The JVM options and classpath below are the ones conf\wrapper.conf hands to
rem the wrapper, minus the wrapper's own bootstrap class. A trimmed classpath
rem does NOT work: the licence code initialises logging through tomcat-juli
rem first.
cd /d "C:\ManageEngine\DesktopCentral_Server\bin"
set CP=..\lib\wrapper.jar;..\lib\trayicon.jar;..\lib\tomcat\tomcat-juli.jar;run.jar;..\tools.jar;..\lib\AdventNetNPrevalent.jar;..\lib\StartupUtils.jar;..\lib\tomcat\commons-logging.jar;..\lib\*;..\lib\AdventNetUpdateManagerInstaller.jar
..\jre\bin\java -server -Dcatalina.home=.. -Dserver.home=.. -Dserver.stats=10000 -Djava.util.logging.manager=org.apache.juli.ClassLoaderLogManager -Djava.util.logging.config.file=../conf/logging.properties -Dlog.dir=.. -Ddb.home=../pgsql -Dcheck.tomcatport=true -Dproduct.home=.. -DDBStartupRetries=120 -Dabnormal.exitcode=60000 -Dfile.encoding=utf8 -Dmysql.home=../mysql -Dpgsql.home=../pgsql -Djava.library.path=../lib/native -cp "%CP%" com.me.devicemanagement.onpremise.start.DCStarter < "C:\dc-eula-answers.txt"
