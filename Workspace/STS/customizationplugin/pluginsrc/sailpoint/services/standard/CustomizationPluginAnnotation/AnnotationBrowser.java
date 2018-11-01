package sailpoint.services.standard.CustomizationPluginAnnotation;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.lang.reflect.Method;
import java.util.ArrayList;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipInputStream;

import org.apache.log4j.Logger;

import sailpoint.services.standard.CustomizationPluginAnnotation.Rule;
import sailpoint.services.standard.CustomizationPluginAnnotation.RuleLibrary;
import sailpoint.services.standard.CustomizationPluginAnnotation.RuleLibraryMethod;

import sailpoint.tools.GeneralException;

public class AnnotationBrowser {
	
	
	
	
	private static Logger log = Logger.getLogger(AnnotationBrowser.class);
	
	private String origFileName;
	private String outFilePth;
	private String pluginName;
	
	
	
	
	AnnotationBrowser(String jarFileName,String outDir,String pluginCustomName)
	{

		origFileName = jarFileName;
		outFilePth = outDir;
		pluginName=pluginCustomName;
	}
	
	
	
	
	private void checkClass(String clsName) throws ClassNotFoundException, GeneralException, FileNotFoundException, UnsupportedEncodingException
	{
		Class<?> clsObj = Class.forName(clsName);
		if(clsObj==null)
		{
			log.error("Class ["+clsName+"] not found");
			return;
		}
		
		log.trace("Class ["+clsName+"] loaded");
		
		
		 
		
		if(clsObj.isAnnotationPresent( RuleLibrary.class))
		{
			log.debug("Class ["+clsName+"] has rule library annotation");
			BshObject ruleLibObject =  BshObject.getRuleLibrary (clsObj,pluginName);
			
			log.debug(ruleLibObject.getRuleCode());
			ruleLibObject.saveToDirectory(outFilePth);
		}
		
		
		if(clsObj.getDeclaredMethods()!=null)
			for(Method mObj : clsObj.getDeclaredMethods())
			{
				
				if(mObj.isAnnotationPresent(Rule.class))
				{
					log.debug("Method ["+mObj.getName()+"] from class ["+clsName+"] has rule annotation");
					BshObject ruleObject =  BshObject.getRule(clsObj,mObj,pluginName);
					log.debug(ruleObject.getRuleCode());
					ruleObject.saveToDirectory(outFilePth);
				}
			}
		
	}
	
	 
	



	private List<String> getClassNamesFromJar(String fileName) throws IOException
	{
		List<String> classNames = new ArrayList<String>();
		ZipInputStream zip = new ZipInputStream(new FileInputStream(fileName));
		for (ZipEntry entry = zip.getNextEntry(); entry != null; entry = zip.getNextEntry()) {
		    if (!entry.isDirectory() && entry.getName().endsWith(".class")) {
		        // This ZipEntry represents a class. Now, what class does it represent?
		        String className = entry.getName().replace('/', '.'); // including ".class"
		        classNames.add(className.substring(0, className.length() - ".class".length()));
		    }
		}
		return classNames;
	}
	
	public void run()
	{
		try {
			log.info("Start Annotation Scanner");
			 
			List<String> classNames = getClassNamesFromJar(origFileName);
			log.trace(classNames);
			if(classNames!=null)
				for(String clsName:classNames)
					checkClass(clsName);
			
			
		} catch (IOException | ClassNotFoundException | GeneralException e) {
			 
			log.error("Run error",e);
		}
	}
	
	public static void main(String[] args) {
		
		 
		if(args.length!=3)
		{
			log.error("Correct args:  path to jar,  path to output dir, plugin name");
			return;
		}
		
		String jarPth = args[0];
		String outXmlPth =  args[1];
		String pluginName =  args[2];
		log.debug("jarPth["+jarPth+"]");	
		log.debug("outXmlPth["+outXmlPth+"]");	
		AnnotationBrowser ab = new AnnotationBrowser(jarPth,outXmlPth,pluginName);
		ab.run();
	}

}
