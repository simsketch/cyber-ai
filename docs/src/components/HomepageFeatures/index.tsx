import React from 'react';
import clsx from 'clsx';
import styles from './styles.module.css';

type FeatureItem = {
  title: string;
  image: string;
  description: JSX.Element;
};

const FeatureList: FeatureItem[] = [
  {
    title: 'AI-Powered Scanning',
    image: '/img/ai-scanning.svg',
    description: (
      <>
        Leverage advanced artificial intelligence to automatically detect and analyze security vulnerabilities in your infrastructure.
      </>
    ),
  },
  {
    title: 'Real-Time Monitoring',
    image: '/img/monitoring.svg',
    description: (
      <>
        Get instant alerts and notifications about security threats with our real-time monitoring system.
      </>
    ),
  },
  {
    title: 'Interactive Visualizations',
    image: '/img/visualization.svg',
    description: (
      <>
        Understand your security posture with interactive 3D visualizations of network topology and attack chains.
      </>
    ),
  },
  {
    title: 'Compliance Tracking',
    image: '/img/compliance.svg',
    description: (
      <>
        Automatically track and report on compliance with major security frameworks like PCI DSS, HIPAA, and GDPR.
      </>
    ),
  },
  {
    title: 'Smart Reporting',
    image: '/img/reporting.svg',
    description: (
      <>
        Generate comprehensive security reports with AI-powered insights and actionable recommendations.
      </>
    ),
  },
  {
    title: 'API Integration',
    image: '/img/api.svg',
    description: (
      <>
        Easily integrate security scanning capabilities into your existing workflows with our comprehensive API.
      </>
    ),
  },
];

function Feature({title, image, description}: FeatureItem) {
  return (
    <div className={clsx('col col--4')}>
      <div className="text--center">
        <img className={styles.featureSvg} src={image} alt={title} />
      </div>
      <div className="text--center padding-horiz--md">
        <h3>{title}</h3>
        <p>{description}</p>
      </div>
    </div>
  );
}

export default function HomepageFeatures(): JSX.Element {
  return (
    <section className={styles.features}>
      <div className="container">
        <div className="row">
          {FeatureList.map((props, idx) => (
            <Feature key={idx} {...props} />
          ))}
        </div>
      </div>
    </section>
  );
}
